#!/usr/bin/env bash
# Carved out for rtk-ai/rtk#1007: rtk's own decision table as a chock pre-tool guard.
# Exit 1 refuses, exit 3 asks (the first line printed is the prompt), exit 0 stays silent.
# Not a security boundary; bypasses are possible via aliases, quoting, or non-standard paths.
set -eu

# rm -rf targets that are never asked about, only refused.
is_dangerous_target() {
    local t="$1"
    # The tilde MUST be quoted on the pattern side; unquoted `~/*` undergoes tilde expansion.
    # `$HOME/...` is checked literally: the guard sees the command BEFORE a shell expands it.
    [[ "$t" == "/" || "$t" == "~" || "$t" == "." || "$t" == ".."         || "$t" == /* || "$t" == "~"/*         || "$t" == '$HOME' || "$t" == '${HOME}'         || "$t" == '$HOME'/* || "$t" == '${HOME}'/* ]]
}

# rtk's safe list: build output a developer deletes all day. Matched on the last path segment.
is_safe_dir() {
    local base="${1##*/}"
    case "$base" in
        node_modules | dist | build | .next | __pycache__ | .cache | tmp | .tmp | coverage | .nyc_output | target | .turbo | .parcel-cache) return 0 ;;
        *) return 1 ;;
    esac
}

# A file whose contents are a credential. Example/template copies stay readable.
is_secret_file() {
    local base="${1##*/}"
    case "$base" in
        .env.example | .env.sample | .env.template | .env.dist | .env.local.example) return 1 ;;
        .env | .env.* | *.pem | *.key | *.p12 | *.pfx | *.jks | *.keystore | id_rsa* | id_ed25519* | id_ecdsa* | id_dsa* | .credentials | credentials | .netrc | .pgpass | .git-credentials) return 0 ;;
    esac
    case "$1" in
        */.ssh/* | */.aws/* | */.gnupg/* | */.kube/config) return 0 ;;
    esac
    return 1
}

# A shell variable name that holds a credential (matched on the NAME, never the value).
is_secret_name() {
    local n="$1"
    shopt -s nocasematch 2>/dev/null || true
    local r=0
    [[ "$n" =~ (api_key|apikey|secret|token|password|passwd|private_key|access_key)$ || "$n" =~ (api_key|apikey|secret|token|password|passwd|private_key|access_key)_ ]] || r=1
    shopt -u nocasematch 2>/dev/null || true
    return $r
}

# Options that consume the NEXT token as their VALUE, dropped before positions are resolved.
_is_value_flag() {
    case "$1" in
        --namespace | --kube-context | --kubeconfig | --context | --region | --profile | --project | --account | --output | --format | --host | --config | --endpoint-url | --cluster | --user | --server | --kube-apiserver | --log-level | --configuration | --chdir | --container | --workdir | --env-file)
            return 0
            ;;
        -u | -g | -p | -H | -o | -n | -C | -w | -d | -U | -h | -P)
            return 0
            ;;
        *) return 1 ;;
    esac
}

all_args=("$@")
flags=()
targets=()
positionals=()
assignments=()
subcommand=""
skip_next=0

for arg in "$@"; do
    if [[ "$skip_next" -eq 1 ]]; then
        skip_next=0
        continue
    fi
    if [[ "$arg" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
        # `VAR=value cmd`: an inline environment assignment, not a program or an operand.
        assignments+=("$arg")
        continue
    fi
    if [[ "$arg" =~ ^- ]]; then
        if _is_value_flag "$arg"; then
            skip_next=1
        fi
        if [[ "$arg" =~ ^-- ]]; then
            flags+=("$arg")
        else
            for ((i=1; i<${#arg}; i++)); do
                flags+=("-${arg:i:1}")
            done
        fi
    else
        positionals+=("$arg")
        case "$arg" in
            git | rm | kubectl | terraform | aws | helm | docker | gcloud | dropdb) ;;
            push | reset | clean | delete | destroy | checkout | branch | exec)
                if [[ -z "$subcommand" ]]; then subcommand="$arg"; fi
                ;;
            *) targets+=("$arg") ;;
        esac
    fi
done

pos_after() {
    local want="$1" off="$2" i
    for i in "${!positionals[@]}"; do
        if [[ "${positionals[i]}" == "$want" ]]; then
            printf '%s' "${positionals[i + off]:-}"
            return 0
        fi
    done
    return 1
}

# The program actually invoked: the first positional that is not a transparent wrapper.
# `rtk` is one: rtk's own hook rewrites `git status` to `rtk git status` before this runs.
cmd_word=""
for _p in "${positionals[@]}"; do
    case "$_p" in
        sudo | env | command | exec | nice | nohup | time | doas | rtk) continue ;;
        *)
            cmd_word="$_p"
            break
            ;;
    esac
done

has_flag() {
    local needle="$1"
    for f in "${flags[@]}"; do
        [[ "$f" == "$needle" ]] && return 0
    done
    return 1
}

# git accepts any unambiguous prefix of a long option; NOT used for push --force, which is
# itself a prefix of the safe --force-with-lease.
has_flag_prefix() {
    local full="$1" min="$2" f
    for f in "${flags[@]}"; do
        [[ ${#f} -ge $min && "$full" == "$f"* ]] && return 0
    done
    return 1
}

has_command() {
    local cmd="$1"
    for a in "${all_args[@]}"; do
        [[ "$a" == "$cmd" ]] && return 0
    done
    return 1
}

# rtk's container rule: inside `docker exec` / `kubectl exec` the paths are the container's,
# so the host-path file checks are skipped. Everything else in the table still applies.
in_container=0
if [[ "$cmd_word" == "docker" || "$cmd_word" == "kubectl" ]] && [[ "$(pos_after "$cmd_word" 1)" == "exec" ]]; then
    in_container=1
fi

ask_reason=""
ask() {
    if [[ -z "$ask_reason" ]]; then ask_reason="$1"; fi
}

# --- Files ------------------------------------------------------------------------------
if has_command "rm" && [[ "$in_container" -eq 0 ]]; then
    if { has_flag "-r" || has_flag "-R" || has_flag "--recursive"; } && { has_flag "-f" || has_flag "--force"; }; then
        for t in "${targets[@]}"; do
            if is_dangerous_target "$t"; then
                echo "BLOCKED: rm -rf targeting '$t' (root, home, parent or absolute path) is not allowed; delete a specific relative path instead." >&2
                exit 1
            fi
        done
        for t in "${targets[@]}"; do
            if ! is_safe_dir "$t"; then
                ask "CONFIRM: rm -rf on '$t' is recursive and unrecoverable; confirm the target, or use a trash/dry-run alternative."
            fi
        done
    fi
fi

# --- Git --------------------------------------------------------------------------------
if has_command "git"; then
    if [[ "$subcommand" == "push" ]]; then
        if has_flag "-f" || has_flag "--force"; then
            echo "BLOCKED: git push --force is not allowed; use --force-with-lease on a feature branch." >&2
            exit 1
        fi
        for t in "${targets[@]}"; do
            if [[ "$t" == +* || "$t" == *:+* ]]; then
                echo "BLOCKED: git push with a '+' force-refspec ('$t') overwrites the remote ref; use --force-with-lease on a feature branch." >&2
                exit 1
            fi
        done
    elif [[ "$subcommand" == "reset" ]]; then
        if has_flag_prefix "--hard" 3; then
            ask "CONFIRM: git reset --hard discards uncommitted changes; confirm, or git stash first."
        fi
    elif [[ "$subcommand" == "clean" ]]; then
        if has_flag "-f" || has_flag_prefix "--force" 3; then
            ask "CONFIRM: git clean -f deletes untracked files; confirm, or run git clean -n to preview."
        fi
    elif [[ "$subcommand" == "checkout" ]]; then
        for t in "${targets[@]}"; do
            if [[ "$t" == "." ]]; then
                ask "CONFIRM: git checkout . discards every uncommitted change in the tree; confirm, or git stash first."
            fi
        done
    elif [[ "$subcommand" == "branch" ]]; then
        if has_flag "-D"; then
            ask "CONFIRM: git branch -D deletes a branch even if unmerged; confirm, or use -d for a merged branch."
        fi
    fi
fi

# --- Secrets ----------------------------------------------------------------------------
case "$cmd_word" in
    cat | head | tail | less | more | bat | strings | xxd | hexdump | base64 | od | nl | tac)
        for t in "${targets[@]}"; do
            if is_secret_file "$t"; then
                echo "BLOCKED: reading a credential-bearing file ('${t##*/}') into the agent's context is not allowed; read the value from the environment where it is needed." >&2
                exit 1
            fi
        done
        ;;
    echo | printf)
        for t in "${targets[@]}"; do
            if [[ "$t" == *'$'* ]]; then
                name="${t#*\$}"; name="${name#\{}"; name="${name%%[^A-Za-z0-9_]*}"
                if [[ -n "$name" ]] && is_secret_name "$name"; then
                    echo "BLOCKED: echoing \$$name would print a credential into the transcript; use it without printing it." >&2
                    exit 1
                fi
            fi
        done
        ;;
esac
for a in "${assignments[@]}"; do
    name="${a%%=*}"
    value="${a#*=}"
    if is_secret_name "$name" && [[ -n "$value" && "$value" != '$'* ]]; then
        echo "BLOCKED: a literal credential is being passed inline as \$$name; export it from a secret store or the environment instead." >&2
        exit 1
    fi
done

# --- Database ---------------------------------------------------------------------------
if [[ "$cmd_word" == "dropdb" ]]; then
    echo "BLOCKED: dropdb is not allowed without approval." >&2
    exit 1
fi
case "$cmd_word" in
    psql | mysql | mariadb | sqlite3 | mongosh | mongo | redis-cli | clickhouse-client)
        sql="${CHOCK_RAW_COMMAND:-$*}"
        shopt -s nocasematch 2>/dev/null || true
        if [[ "$sql" =~ drop[[:space:]]+(table|database|schema|collection) ]]; then
            echo "BLOCKED: a DROP statement through $cmd_word is not allowed; take a backup and run it by hand." >&2
            exit 1
        fi
        if [[ "$sql" =~ (^|[^a-z])truncate([[:space:]]|$) ]]; then
            echo "BLOCKED: a TRUNCATE statement through $cmd_word is not allowed; take a backup and run it by hand." >&2
            exit 1
        fi
        if [[ "$sql" =~ delete[[:space:]]+from[[:space:]]+[a-z0-9_.\"\`]+[[:space:]]*(;|$) ]]; then
            echo "BLOCKED: DELETE FROM without a WHERE clause through $cmd_word is not allowed; scope the delete or run it by hand." >&2
            exit 1
        fi
        if [[ "$sql" =~ (^|[^a-z])(flushall|flushdb)([^a-z]|$) ]]; then
            echo "BLOCKED: FLUSHALL/FLUSHDB through $cmd_word is not allowed; delete keys by pattern instead." >&2
            exit 1
        fi
        shopt -u nocasematch 2>/dev/null || true
        ;;
esac

# --- Docker -----------------------------------------------------------------------------
if [[ "$cmd_word" == "docker" ]]; then
    d1="$(pos_after docker 1)"
    d2="$(pos_after docker 2)"
    if [[ "$d1" == "system" && "$d2" == "prune" ]]; then
        ask "CONFIRM: docker system prune removes every stopped container, unused network and dangling image; confirm, or prune one resource type."
    elif [[ "$d1" == "volume" && "$d2" == "prune" ]]; then
        ask "CONFIRM: docker volume prune deletes every unused volume's data; confirm, or remove one named volume."
    elif [[ ( "$d1" == "container" || "$d1" == "image" || "$d1" == "network" || "$d1" == "builder" ) && "$d2" == "prune" ]]; then
        ask "CONFIRM: docker $d1 prune sweeps every unused $d1; confirm, or remove one by name."
    elif [[ "$d1" == "volume" && "$d2" == "rm" ]]; then
        echo "BLOCKED: docker volume rm destroys the volume's data and is not allowed without approval." >&2
        exit 1
    elif [[ "$d1" == "rm" ]]; then
        if has_flag "-f" || has_flag "--force"; then
            for t in "${targets[@]}"; do
                if [[ "$t" == '$('* || "$t" == '`'* ]]; then
                    ask "CONFIRM: docker rm -f over a command substitution removes every container it lists; confirm, or name the containers."
                fi
            done
            raw="${CHOCK_RAW_COMMAND-}"
            if [[ "$raw" == *'$(docker ps'* || "$raw" == *'`docker ps'* ]]; then
                ask "CONFIRM: docker rm -f over a command substitution removes every container it lists; confirm, or name the containers."
            fi
        fi
    fi
fi

# --- Cloud and cluster (kept from block-destructive-commands; not in rtk's table) --------
if has_command "kubectl" && [[ "$subcommand" == "delete" ]]; then
    echo "BLOCKED: kubectl delete is not allowed without approval." >&2
    exit 1
fi
if has_command "terraform" && [[ "$subcommand" == "destroy" ]]; then
    echo "BLOCKED: terraform destroy is not allowed without approval." >&2
    exit 1
fi
if has_command "aws" && has_command "s3"; then
    aws_action="$(pos_after s3 1)"
    if [[ "$aws_action" == "rm" ]] && has_flag "--recursive"; then
        echo "BLOCKED: aws s3 rm --recursive is not allowed without approval." >&2
        exit 1
    fi
    if [[ "$aws_action" == "rb" ]] && has_flag "--force"; then
        echo "BLOCKED: aws s3 rb --force is not allowed without approval." >&2
        exit 1
    fi
fi
if has_command "helm"; then
    helm_action="$(pos_after helm 1)"
    if [[ "$helm_action" == "uninstall" || "$helm_action" == "delete" ]]; then
        echo "BLOCKED: helm uninstall/delete is not allowed without approval." >&2
        exit 1
    fi
fi
if has_command "gcloud" && has_command "delete"; then
    echo "BLOCKED: gcloud delete is not allowed without approval." >&2
    exit 1
fi

# --- PowerShell / cmd (kept from block-destructive-commands) -----------------------------
raw="${CHOCK_RAW_COMMAND-}"
if [ -n "$raw" ] && [[ "$in_container" -eq 0 ]]; then
    shopt -s nocasematch 2>/dev/null || true
    verb_re='(^|[|;&[:space:]])(remove-item|ri|rd|rmdir|del|erase)([[:space:]]|$)'
    recurse_re='(-recurse|-r([[:space:]]|$)|/s([[:space:]]|$))'
    target_re='([a-z]:[\\/]|[a-z]:([[:space:]]|$)|(^|[[:space:]])[\\/]([[:space:]]|$)|~|\$home|\$env:userprofile|\$env:home)'
    if [[ "$raw" =~ $verb_re ]] && [[ "$raw" =~ $recurse_re ]] && [[ "$raw" =~ $target_re ]]; then
        echo "BLOCKED: destructive PowerShell/cmd removal targeting a drive root or home path is not allowed without approval." >&2
        exit 1
    fi
    shopt -u nocasematch 2>/dev/null || true
fi

if [[ -n "$ask_reason" ]]; then
    echo "$ask_reason" >&2
    exit 3
fi
exit 0
