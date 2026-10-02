"""The one verdict table block-destructive-commands and rtk-dangerous-actions-blocker both read (shared byte for byte)."""

from typing import NamedTuple

TABLE_VERSION = "1.0.0"
BLOCK, ASK = 1, 3


class Row(NamedTuple):
    """A verdict and its message; `{0}` is replaced by what the command named (a path, a ref, a verb)."""

    verdict: int
    text: str


_PERSON = " is refused. Ask the person to run it themselves; prefer a scoped or dry-run form."
_REWRITE = " rewrites remote history. Rebase onto the remote and push fast-forward; a rewrite is the person's call."


def _block(what: str) -> Row:
    return Row(BLOCK, what + _PERSON)


def _ask(text: str) -> Row:
    return Row(ASK, text)


TABLE: dict[str, Row] = {
    # files and devices
    "rm-rf": _block("rm -rf targeting '{0}' (absolute path, home, '.', '..' or the working directory)"),
    "rm-root": _block("rm -r targeting '{0}' (root, a system directory or home)"),
    "rm-relative": _ask(
        "rm -rf on '{0}' is recursive and unrecoverable; confirm the target, or use a trash/dry-run alternative."
    ),
    "unlink-root": _block("{0} on root, a system directory or home"),
    "mv-root": _block("mv of '{0}' (root, a system directory or home)"),
    "chmod-root": _block("recursive chmod {0} on root, a system directory or home"),
    "chown-root": _block("recursive {0} on root, a system directory or home"),
    "dd-device": _block("dd writing to the device '{0}'"),
    "mkfs": _block("{0} (it formats a device)"),
    "find-delete": _block("find with -delete/-exec rm rooted at '{0}'"),
    "shred": _block("{0} (it discards the data, not just the link)"),
    "wipefs": _block("wipefs -a/-o (erases filesystem signatures)"),
    "powershell-remove": _block(
        "recursive PowerShell/cmd removal targeting a drive path (any C:\\...), root, home, '.' or '..'"
    ),
    # lockout and sabotage
    "authorized-keys": _block("overwriting or deleting '{0}' (it can lock every key out of the account)"),
    "account-lock": _block("{0} (it locks an account)"),
    "chattr-immutable": _block("chattr {0} (it makes files immutable, even to root's rm)"),
    "kill-all": _block("kill aimed at pid -1 (every process the user can signal)"),
    "kill-pattern": _ask("{0} signals every process whose name or command line matches; confirm, or kill one pid."),
    "crontab-remove": _block("crontab -r (it deletes the whole crontab)"),
    "systemctl-disable": _ask(
        "systemctl {0} stops a unit from starting; confirm the unit, or stop it for this boot only."
    ),
    # git
    "push-force": Row(BLOCK, "git push --force" + _REWRITE),
    "push-force-refspec": Row(BLOCK, "git push with a '+' force-refspec ('{0}')" + _REWRITE),
    "push-delete": _block("git push {0} (it deletes refs on the remote)"),
    "push-mirror": _block("git push --mirror (it overwrites and deletes every remote ref)"),
    "push-lease-bare": _ask(
        "git push --force-with-lease without a value trusts whatever was last fetched; confirm, or name the ref and its expected sha (--force-with-lease=<ref>:<sha>)."
    ),
    "reset-hard": _block("git reset --hard"),
    "clean-force": _block("git clean -f"),
    "checkout-all": _block("git checkout of the whole tree ('{0}')"),
    "restore-all": _block("git restore of the whole tree ('{0}')"),
    "stash-drop": _ask("git stash {0} deletes stashed work; confirm, or git stash list and drop one entry."),
    "branch-force-delete": _ask(
        "git branch -D deletes a branch even if unmerged; confirm, or use -d for a merged branch."
    ),
    "history-rewrite": _block("git {0} (it destroys history or unreachable objects)"),
    # infrastructure, cloud, platforms and data
    "kubectl-delete": _block("kubectl delete"),
    "kubectl-drain": _ask("kubectl drain evicts every pod on the node; confirm the node, or cordon it first."),
    "iac-destroy": _block("{0}"),
    "iac-auto-approve": _ask(
        "{0} -auto-approve applies without showing the plan; confirm, or run plan and apply the saved plan."
    ),
    "cloud-delete": _block("{0}"),
    "helm-uninstall": _block("helm uninstall/delete"),
    "docker-volume": _block("docker volume rm/prune (it destroys volume data)"),
    "docker-system-prune": _block("docker system prune"),
    "compose-down-volumes": _block("{0} down -v (it deletes the project's volumes)"),
    "docker-prune": _ask("docker {0} prune sweeps every unused {0}; confirm, or remove one by name."),
    "docker-rm-substituted": _ask(
        "docker rm -f over a command substitution removes every container it lists; confirm, or name the containers."
    ),
    "drop-database": _block("{0}"),
    "sql": _block("{0}"),
    "api-delete": _ask(
        "{0} deletes through an infrastructure API with credentials; confirm the target, or use the provider's CLI with a dry run."
    ),
}
