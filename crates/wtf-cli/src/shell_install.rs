use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const START_MARKER: &str = "# >>> wtf shell integration >>>";
const END_MARKER: &str = "# <<< wtf shell integration <<<";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    fn parse(value: &str) -> Option<Self> {
        match Path::new(value)
            .file_name()?
            .to_string_lossy()
            .trim_start_matches('-')
        {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }
}

/// Installs hooks into the detected shell's interactive startup configuration.
pub fn install() -> Result<String, String> {
    let shell = detect_shell()?;
    let home = env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| "Cannot install shell integration: HOME is not set.".to_owned())?;
    let path = rc_path(shell, Path::new(&home));
    let executable =
        env::current_exe().map_err(|error| format!("Cannot locate the wtf executable: {error}"))?;
    if shell == Shell::Fish {
        install_fish_at(&path, &executable)
    } else {
        install_at(shell, &path, &executable)
    }
}

/// Removes only the WTF-owned hook from the detected shell's startup configuration.
pub fn uninstall() -> Result<String, String> {
    let shell = detect_shell()?;
    let home = env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| "Cannot uninstall shell integration: HOME is not set.".to_owned())?;
    let path = rc_path(shell, Path::new(&home));
    if shell == Shell::Fish {
        uninstall_fish_at(&path)
    } else {
        uninstall_at(&path)
    }
}

fn detect_shell() -> Result<Shell, String> {
    if let Some(shell) = detect_parent_shell() {
        return Ok(shell);
    }
    if let Some(shell) =
        env::var_os("SHELL").and_then(|value| Path::new(&value).to_str().and_then(Shell::parse))
    {
        return Ok(shell);
    }

    Err("Cannot detect Bash, Zsh, or Fish from SHELL or the parent process.".to_owned())
}

fn detect_parent_shell() -> Option<Shell> {
    let pid = std::process::id().to_string();
    let parent_pid = Command::new("ps")
        .args(["-p", pid.as_str(), "-o", "ppid="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())?;

    Command::new("ps")
        .args(["-p", parent_pid.as_str(), "-o", "comm="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|name| Shell::parse(name.trim()))
}

fn rc_path(shell: Shell, home: &Path) -> PathBuf {
    match shell {
        Shell::Bash => home.join(".bashrc"),
        Shell::Zsh => env::var_os("ZDOTDIR")
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.to_path_buf())
            .join(".zshrc"),
        Shell::Fish => fish_rc_path(home, env::var_os("XDG_CONFIG_HOME").as_deref()),
    }
}

fn fish_rc_path(home: &Path, xdg_config_home: Option<&OsStr>) -> PathBuf {
    let config_home = xdg_config_home
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    config_home.join("fish").join("conf.d").join("wtf.fish")
}

fn install_at(shell: Shell, rc_path: &Path, executable: &Path) -> Result<String, String> {
    let original = read_optional_rc(rc_path)?;
    let existing_range = block_range(&original)?;
    let outside_block = match existing_range {
        Some((start, end)) => format!("{}{}", &original[..start], &original[end..]),
        None => original.clone(),
    };

    if shell == Shell::Bash && has_debug_trap(&outside_block) {
        return Err(format!(
            "Cannot install WTF shell integration in {}: an existing Bash DEBUG trap may conflict. Remove or integrate that trap first.",
            rc_path.display()
        ));
    }

    let block = hook_block(shell, executable)?;
    let updated = if let Some((start, end)) = existing_range {
        if &original[start..end] == block.as_str() {
            return Ok(format!(
                "WTF shell integration is already installed in {}.",
                rc_path.display()
            ));
        }
        format!("{}{}{}", &original[..start], block, &original[end..])
    } else {
        append_block(&original, &block)
    };

    write_rc_atomically(rc_path, updated.as_bytes())
        .map_err(|error| format!("Cannot update {}: {error}", rc_path.display()))?;
    Ok(format!(
        "Installed WTF shell integration in {}. Start a new shell or source the file to activate it.",
        rc_path.display()
    ))
}

fn install_fish_at(path: &Path, executable: &Path) -> Result<String, String> {
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "Cannot install WTF shell integration: {} already exists and is not an owned regular file.",
                    path.display()
                ));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("Cannot inspect {}: {error}", path.display())),
    };
    let original = read_optional_rc(path)?;
    let existing_range = block_range(&original)?;
    if existed && existing_range.is_none() {
        return Err(format!(
            "Cannot install WTF shell integration: {} already exists and is not owned by WTF.",
            path.display()
        ));
    }

    let block = hook_block(Shell::Fish, executable)?;
    let updated = if let Some((start, end)) = existing_range {
        if &original[start..end] == block.as_str() {
            return Ok(format!(
                "WTF shell integration is already installed in {}.",
                path.display()
            ));
        }
        format!("{}{}{}", &original[..start], block, &original[end..])
    } else {
        append_block(&original, &block)
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Cannot create {}: {error}", parent.display()))?;
    }
    write_rc_atomically(path, updated.as_bytes())
        .map_err(|error| format!("Cannot update {}: {error}", path.display()))?;
    Ok(format!(
        "Installed WTF shell integration in {}. Start a new Fish shell to activate it.",
        path.display()
    ))
}

fn uninstall_fish_at(path: &Path) -> Result<String, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(format!(
                "WTF shell integration is not installed in {}.",
                path.display()
            ));
        }
        Err(error) => return Err(format!("Cannot inspect {}: {error}", path.display())),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "Cannot uninstall WTF shell integration: {} is not an owned regular file.",
            path.display()
        ));
    }
    let original = read_optional_rc(path)?;
    let Some((start, end)) = block_range(&original)? else {
        return Ok(format!(
            "WTF shell integration is not installed in {}.",
            path.display()
        ));
    };
    let updated = format!("{}{}", &original[..start], &original[end..]);
    if updated.is_empty() {
        fs::remove_file(path)
            .map_err(|error| format!("Cannot remove {}: {error}", path.display()))?;
    } else {
        write_rc_atomically(path, updated.as_bytes())
            .map_err(|error| format!("Cannot update {}: {error}", path.display()))?;
    }
    Ok(format!(
        "Removed WTF shell integration from {}.",
        path.display()
    ))
}

fn uninstall_at(rc_path: &Path) -> Result<String, String> {
    let original = match read_optional_rc(rc_path) {
        Ok(contents) => contents,
        Err(error) => return Err(format!("Cannot read {}: {error}", rc_path.display())),
    };
    let Some((start, end)) = block_range(&original)? else {
        return Ok(format!(
            "WTF shell integration is not installed in {}.",
            rc_path.display()
        ));
    };
    let updated = format!("{}{}", &original[..start], &original[end..]);
    write_rc_atomically(rc_path, updated.as_bytes())
        .map_err(|error| format!("Cannot update {}: {error}", rc_path.display()))?;
    Ok(format!(
        "Removed WTF shell integration from {}. Restart the shell or source the file to deactivate it.",
        rc_path.display()
    ))
}

fn read_optional_rc(path: &Path) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("Cannot read {}: {error}", path.display())),
    }
}

fn block_range(contents: &str) -> Result<Option<(usize, usize)>, String> {
    let mut start = None;
    let mut end = None;
    let mut offset = 0;

    for line in contents.split_inclusive('\n') {
        let marker = line.trim_end_matches('\n').trim_end_matches('\r');
        if marker == START_MARKER {
            if start.is_some() || end.is_some() {
                return Err("Shell rc file contains duplicate or malformed WTF markers.".to_owned());
            }
            start = Some(offset);
        } else if marker == END_MARKER {
            if start.is_none() || end.is_some() {
                return Err("Shell rc file contains duplicate or malformed WTF markers.".to_owned());
            }
            end = Some(offset + line.len());
        }
        offset += line.len();
    }

    match (start, end) {
        (None, None) => Ok(None),
        (Some(start), Some(end)) if start < end => Ok(Some((start, end))),
        _ => Err("Shell rc file contains an incomplete WTF marker block.".to_owned()),
    }
}

fn append_block(contents: &str, block: &str) -> String {
    let mut updated = contents.to_owned();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(block);
    updated
}

fn has_debug_trap(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        tokens.iter().enumerate().any(|(index, token)| {
            if !token
                .trim_matches(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_'
                })
                .eq_ignore_ascii_case("trap")
            {
                return false;
            }
            let args = &tokens[index + 1..];
            if args.iter().any(|arg| *arg == "-p" || *arg == "-l") {
                return false;
            }
            args.iter().any(|arg| {
                arg.trim_matches(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_'
                })
                .eq_ignore_ascii_case("DEBUG")
            })
        })
    })
}

fn hook_block(shell: Shell, executable: &Path) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "The wtf executable path is not valid UTF-8.".to_owned())?;
    let quoted_executable = if shell == Shell::Fish {
        fish_quote(executable)
    } else {
        shell_quote(executable)
    };
    let hook = match shell {
        Shell::Bash => bash_hook(&quoted_executable),
        Shell::Zsh => zsh_hook(&quoted_executable),
        Shell::Fish => fish_hook(&quoted_executable),
    };
    Ok(format!("{START_MARKER}\n{hook}{END_MARKER}\n"))
}

fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn bash_hook(executable: &str) -> String {
    format!(
        r#"if [[ -n ${{BASH_VERSION-}} && $- == *i* ]]; then
    __wtf_capture_bin={executable}
    if [[ -z ${{__wtf_capture_loaded-}} ]]; then
        __wtf_capture_is_wtf() {{
            case " $1 " in
                *[![:alnum:]_]wtf[![:alnum:]_]*) return 0 ;;
                *) return 1 ;;
            esac
        }}
        __wtf_capture_preexec() {{
            [[ $BASH_COMMAND == __wtf_capture_precmd ]] && return 0
            if [[ ${{__wtf_capture_pending:-0}} == 0 ]]; then
                __wtf_capture_pending=1
                __wtf_capture_started_elapsed=$SECONDS
                __wtf_capture_line=$BASH_COMMAND
            fi
        }}
        __wtf_capture_precmd() {{
            local __wtf_capture_status=$?
            if [[ ${{__wtf_capture_pending:-0}} == 1 ]]; then
                local __wtf_capture_history=
                if [[ -t 0 ]]; then
                    __wtf_capture_history=$(builtin fc -ln -1 2>/dev/null) || __wtf_capture_history=
                    while [[ $__wtf_capture_history == [[:space:]]* ]]; do
                        __wtf_capture_history=${{__wtf_capture_history#?}}
                    done
                    if [[ -n $__wtf_capture_history && $__wtf_capture_history == "$__wtf_capture_line"* ]]; then
                        __wtf_capture_line=$__wtf_capture_history
                    fi
                fi
                if [[ $__wtf_capture_status -ne 0 ]] && ! __wtf_capture_is_wtf "$__wtf_capture_line"; then
                    local __wtf_capture_finish=
                    __wtf_capture_finish=$(command date +%s 2>/dev/null) || __wtf_capture_finish=
                    if [[ $__wtf_capture_finish =~ ^[0-9]+$ ]]; then
                        local __wtf_capture_start=$((__wtf_capture_finish - (SECONDS - __wtf_capture_started_elapsed)))
                        "$__wtf_capture_bin" __record bash "$__wtf_capture_status" "$__wtf_capture_start" "$__wtf_capture_finish" "$PWD" "$__wtf_capture_line" >/dev/null 2>&1 || :
                    fi
                fi
                __wtf_capture_pending=0
            fi
            return "$__wtf_capture_status"
        }}
        if [[ -z $(builtin trap -p DEBUG) ]]; then
            trap '__wtf_capture_preexec' DEBUG
            __wtf_capture_pc_decl=$(declare -p PROMPT_COMMAND 2>/dev/null) || __wtf_capture_pc_decl=
            if [[ $__wtf_capture_pc_decl == *'PROMPT_COMMAND=('* ]]; then
                PROMPT_COMMAND=(__wtf_capture_precmd "${{PROMPT_COMMAND[@]}}")
            else
                PROMPT_COMMAND="__wtf_capture_precmd${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}"
            fi
            __wtf_capture_loaded=1
        elif [[ -z ${{__wtf_capture_conflict_warned-}} ]]; then
            __wtf_capture_conflict_warned=1
            printf '%s\n' 'wtf: shell integration not activated because a Bash DEBUG trap is already installed.' >&2
        fi
    fi
fi
"#
    )
}

fn zsh_hook(executable: &str) -> String {
    format!(
        r#"if [[ -n ${{ZSH_VERSION-}} && -o interactive ]]; then
    __wtf_capture_bin={executable}
    if [[ -z ${{__wtf_capture_loaded-}} ]]; then
        zmodload zsh/datetime 2>/dev/null || true
        autoload -Uz add-zsh-hook
        __wtf_capture_is_wtf() {{
            case " $1 " in
                *[![:alnum:]_]wtf[![:alnum:]_]*) return 0 ;;
                *) return 1 ;;
            esac
        }}
        __wtf_capture_preexec() {{
            __wtf_capture_line=$1
            __wtf_capture_pending=1
            if (( ${{+EPOCHSECONDS}} )); then
                __wtf_capture_started_epoch=$EPOCHSECONDS
            else
                __wtf_capture_started_elapsed=$SECONDS
            fi
        }}
        __wtf_capture_precmd() {{
            local __wtf_capture_status=$?
            if [[ ${{__wtf_capture_pending:-0}} == 1 ]]; then
                if (( __wtf_capture_status != 0 )) && ! __wtf_capture_is_wtf "$__wtf_capture_line"; then
                    local __wtf_capture_finish='' __wtf_capture_start=''
                    if (( ${{+EPOCHSECONDS}} )); then
                        __wtf_capture_finish=$EPOCHSECONDS
                        __wtf_capture_start=${{__wtf_capture_started_epoch:-$__wtf_capture_finish}}
                    else
                        __wtf_capture_finish=$(command date +%s 2>/dev/null) || __wtf_capture_finish=''
                        if [[ $__wtf_capture_finish == <-> ]]; then
                            __wtf_capture_start=$((__wtf_capture_finish - (SECONDS - __wtf_capture_started_elapsed)))
                        fi
                    fi
                    if [[ $__wtf_capture_finish == <-> && $__wtf_capture_start == <-> ]]; then
                        "$__wtf_capture_bin" __record zsh "$__wtf_capture_status" "$__wtf_capture_start" "$__wtf_capture_finish" "$PWD" "$__wtf_capture_line" >/dev/null 2>&1 || true
                    fi
                fi
                __wtf_capture_pending=0
            fi
            return "$__wtf_capture_status"
        }}
        precmd_functions=(__wtf_capture_precmd ${{precmd_functions[@]}})
        add-zsh-hook preexec __wtf_capture_preexec
        __wtf_capture_loaded=1
    fi
fi
"#
    )
}
fn fish_hook(executable: &str) -> String {
    format!(
        r#"if status is-interactive
    set -g __wtf_capture_bin {executable}
    if not set -q __wtf_capture_loaded
        function __wtf_capture_preexec --on-event fish_preexec
            set -g __wtf_capture_line "$argv[1]"
            set -g __wtf_capture_pwd "$PWD"
        end
        function __wtf_capture_postexec --on-event fish_postexec
            set -l __wtf_capture_status $status
            if test "$__wtf_capture_status" -ne 0
                if not string match -rq '(^|[^[:alnum:]_])wtf([^[:alnum:]_]|$)' -- "$__wtf_capture_line"
                    set -l __wtf_capture_finish (command date +%s 2>/dev/null)
                    if string match -rq '^[0-9]+$' -- "$__wtf_capture_finish"
                        set -l __wtf_capture_elapsed 0
                        if set -q CMD_DURATION
                            if string match -rq '^[0-9]+$' -- "$CMD_DURATION"
                                set __wtf_capture_elapsed "$CMD_DURATION"
                            end
                        end
                        set -l __wtf_capture_start (math "$__wtf_capture_finish - floor($__wtf_capture_elapsed / 1000)" 2>/dev/null)
                        if string match -rq '^[0-9]+$' -- "$__wtf_capture_start"
                            "$__wtf_capture_bin" __record fish "$__wtf_capture_status" "$__wtf_capture_start" "$__wtf_capture_finish" "$__wtf_capture_pwd" "$__wtf_capture_line" >/dev/null 2>&1
                            or true
                        end
                    end
                end
            end
            return "$__wtf_capture_status"
        end
        set -g __wtf_capture_loaded 1
    end
end
"#
    )
}

fn write_rc_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    let target = match fs::symlink_metadata(path) {
        Ok(_) => fs::canonicalize(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => path.to_path_buf(),
        Err(error) => return Err(error),
    };
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rc path has no file name"))?;
    let existing_permissions = fs::metadata(&target)
        .ok()
        .map(|metadata| metadata.permissions());

    for attempt in 0..100_u32 {
        let mut temporary_name = file_name.to_os_string();
        temporary_name.push(format!(".wtf-tmp-{}-{attempt}", std::process::id()));
        let temporary = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };

        let result = write_and_replace(
            file,
            &temporary,
            &target,
            contents,
            existing_permissions.as_ref(),
        );
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary rc file",
    ))
}

fn write_and_replace(
    mut file: File,
    temporary: &Path,
    target: &Path,
    contents: &[u8],
    existing_permissions: Option<&fs::Permissions>,
) -> io::Result<()> {
    file.write_all(contents)?;
    if let Some(permissions) = existing_permissions {
        file.set_permissions(permissions.clone())?;
    }
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn executable(dir: &Path) -> PathBuf {
        dir.join("bin with 'quote'/wtf")
    }
    #[test]
    fn parses_login_shell_process_names() {
        assert_eq!(Shell::parse("-bash"), Some(Shell::Bash));
        assert_eq!(Shell::parse("-zsh"), Some(Shell::Zsh));
        assert_eq!(Shell::parse("-fish"), Some(Shell::Fish));
    }

    #[test]
    fn install_is_idempotent_and_quotes_executable_path() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        let executable = executable(dir.path());
        install_at(Shell::Bash, &rc, &executable).unwrap();
        let first = fs::read_to_string(&rc).unwrap();
        assert!(first.contains(&shell_quote(executable.to_str().unwrap())));
        assert!(first.contains("__wtf_capture_precmd"));
        assert!(install_at(Shell::Bash, &rc, &executable)
            .unwrap()
            .contains("already installed"));
        assert_eq!(fs::read_to_string(rc).unwrap(), first);
    }

    #[test]
    fn installation_and_removal_preserve_unrelated_rc_content() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        let before = "# user setting\nexport EDITOR=vi\n";
        fs::write(&rc, before).unwrap();
        install_at(Shell::Zsh, &rc, &executable(dir.path())).unwrap();
        let installed = fs::read_to_string(&rc).unwrap();
        assert!(installed.starts_with(before));
        assert_eq!(installed.matches(START_MARKER).count(), 1);
        assert!(installed.contains("add-zsh-hook preexec"));
        uninstall_at(&rc).unwrap();
        assert_eq!(fs::read_to_string(rc).unwrap(), before);
    }

    #[test]
    fn uninstall_removes_only_the_marked_block() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        let before = "before\n";
        let after = "\n# user content after the integration\n";
        let block = hook_block(Shell::Bash, &executable(dir.path())).unwrap();
        fs::write(&rc, format!("{before}{block}{after}")).unwrap();
        uninstall_at(&rc).unwrap();
        assert_eq!(fs::read_to_string(rc).unwrap(), format!("{before}{after}"));
    }

    #[test]
    fn bash_install_refuses_an_existing_debug_trap() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        fs::write(&rc, "trap 'keep_me' DEBUG\n").unwrap();
        let error = install_at(Shell::Bash, &rc, &executable(dir.path())).unwrap_err();
        assert!(error.contains("DEBUG trap"));
        assert_eq!(fs::read_to_string(rc).unwrap(), "trap 'keep_me' DEBUG\n");
    }

    #[test]
    fn malformed_markers_fail_without_changing_the_rc_file() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        let contents = format!("{START_MARKER}\nuser data\n");
        fs::write(&rc, &contents).unwrap();
        assert!(uninstall_at(&rc).is_err());
        assert_eq!(fs::read_to_string(rc).unwrap(), contents);
    }

    #[test]
    fn fish_config_path_uses_xdg_or_home_fallback() {
        let dir = tempdir().unwrap();
        let xdg = dir.path().join("xdg config");
        assert_eq!(
            fish_rc_path(dir.path(), Some(xdg.as_os_str())),
            xdg.join("fish/conf.d/wtf.fish")
        );
        assert_eq!(
            fish_rc_path(dir.path(), None),
            dir.path().join(".config/fish/conf.d/wtf.fish")
        );
    }

    #[test]
    fn fish_install_is_idempotent_and_uninstall_preserves_other_content() {
        let dir = tempdir().unwrap();
        let xdg = dir.path().join("xdg");
        let config_dir = xdg.join("fish");
        fs::create_dir_all(&config_dir).unwrap();
        let config_file = config_dir.join("config.fish");
        fs::write(&config_file, "set -g fish_greeting ''\n").unwrap();
        let path = fish_rc_path(dir.path(), Some(xdg.as_os_str()));
        let executable = executable(dir.path());

        install_fish_at(&path, &executable).unwrap();
        let installed = fs::read_to_string(&path).unwrap();
        assert!(installed.contains("fish_preexec"));
        assert!(installed.contains("fish_postexec"));
        assert!(installed.contains("__record fish"));
        assert!(install_fish_at(&path, &executable)
            .unwrap()
            .contains("already installed"));
        assert_eq!(fs::read_to_string(&path).unwrap(), installed);
        assert_eq!(
            fs::read_to_string(&config_file).unwrap(),
            "set -g fish_greeting ''\n"
        );

        fs::write(&path, format!("{installed}# user addition\n")).unwrap();
        uninstall_fish_at(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "# user addition\n");
        assert_eq!(
            fs::read_to_string(&config_file).unwrap(),
            "set -g fish_greeting ''\n"
        );
    }

    #[test]
    fn fish_install_refuses_unowned_collision_and_removes_its_own_file() {
        let dir = tempdir().unwrap();
        let path = fish_rc_path(dir.path(), None);
        let executable = executable(dir.path());

        install_fish_at(&path, &executable).unwrap();
        uninstall_fish_at(&path).unwrap();
        assert!(!path.exists());

        fs::write(&path, "# user-owned file\n").unwrap();
        assert!(install_fish_at(&path, &executable).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "# user-owned file\n");
    }
}
