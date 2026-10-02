"""Regression cases from the adversarial review of table 1.0.0: value flags that shift a verb, flag clusters and
abbreviations, path spellings, and the near misses that must stay allowed. Same shape as guard_cases_destructive."""

from __future__ import annotations

CASES: list[tuple[str, str | None]] = [
    # value flags before the verb must not move it out of reach (main blocked the aws and docker forms)
    ("aws --cli-read-timeout 5 s3 rm s3://b --recursive", "cloud-delete"),
    ("aws --cli-connect-timeout 5 s3 rb s3://b --force", "cloud-delete"),
    ("aws --cli-read-timeout 5 s3api delete-bucket --bucket b", "cloud-delete"),
    ("docker --tlscacert ca.pem system prune", "docker-system-prune"),
    ("docker --tlscert c.pem volume rm v", "docker-volume"),
    ("docker --log-format json system prune", "docker-system-prune"),
    ("docker --tlskey k.pem image prune", "docker-prune"),
    ("pulumi -C infra destroy", "iac-destroy"),
    ("pulumi --cwd infra --stack prod destroy", "iac-destroy"),
    ("terragrunt --terragrunt-working-dir x destroy", "iac-destroy"),
    ("terragrunt --working-dir x destroy", "iac-destroy"),
    ("supabase --workdir x db reset", "cloud-delete"),
    ("vercel --token t rm proj", "cloud-delete"),
    ("eksctl --verbose 4 delete cluster", "cloud-delete"),
    ("docker compose --ansi never down -v", "compose-down-volumes"),
    ("docker-compose --progress plain down -v", "compose-down-volumes"),
    ("chown -R --reference=/tmp /etc", "chown-root"),
    ("chmod -R --reference=/tmp /usr", "chmod-root"),
    # clusters and getopt abbreviations
    ('curl -sX DELETE -H "Authorization: Bearer t" https://api.github.com/repos/o/r', "api-delete"),
    ('curl -sSfXDELETE -H "Authorization: Bearer t" https://api.github.com/repos/o/r', "api-delete"),
    ("curl -X DELETE -su me:$PW https://api.digitalocean.com/v2/droplets/1", "api-delete"),
    ("rm --rec -f /etc", "rm-rf"),
    ("rm --r --f /", "rm-rf"),
    ("usermod --loc root", "account-lock"),
    ("passwd --lock root", "account-lock"),
    # path spellings
    ("rm -r ~root", "rm-root"),
    ("rm -rf ~deploy/", "rm-root"),
    ("rm -r ~/.", "rm-root"),
    ("rm -r $HOME/.", "rm-root"),
    ("rm -rf ~+", "rm-rf"),
    ("rm -r ~/projects/old", None),
    ("dd if=x of=//dev/sda", "dd-device"),
    ("dd if=x of=/./dev/sda", "dd-device"),
    ("chmod -R 1777 /", "chmod-root"),
    ("chmod -R u=rwx,go=rwx /", "chmod-root"),
    ("chattr =i f", "chattr-immutable"),
    ("kill -9 -1 1234", "kill-all"),
    # git pathspecs and pruning
    ("git restore ':(top)'", "restore-all"),
    ("git restore ':/*'", "restore-all"),
    ("git restore ..", "restore-all"),
    ("git checkout -- ../..", "checkout-all"),
    ("git prune", "history-rewrite"),
    ("git prune --expire now", "history-rewrite"),
    ("git prune --expire=2.weeks.ago", None),
    ("git prune -n", None),
    ("git gc --prune=0", "history-rewrite"),
    ("git gc --prune=2.weeks.ago", None),
    # wider cloud coverage
    ("doctl compute droplet rm d", "cloud-delete"),
    ("doctl compute droplet del d", "cloud-delete"),
    ("az vm delete -n web --yes", "cloud-delete"),
    ("az aks delete -n k -g rg", "cloud-delete"),
    ("az vm list", None),
    ("aws dynamodb delete-table --table-name t", "cloud-delete"),
    ("aws lambda delete-function --function-name f", "cloud-delete"),
    ("aws secretsmanager delete-secret --secret-id s", "cloud-delete"),
    ("aws dynamodb scan --table-name t", None),
    # SQL comments and case; heredoc bodies fed to a shell
    ("psql -c 'DROP/**/TABLE x'", "sql"),
    ("psql -c 'delete from users -- tidy'", "sql"),
    ("psql -c 'delete from users where id = 1 -- tidy'", None),
    ("mysqladmin Drop db", "drop-database"),
    ("psql <<SQL\nselect 1; --\nDROP TABLE x;\nSQL", "sql"),
    ("bash <<EOF\nrm -rf /\nEOF", "rm-rf"),
    ("sh <<'EOF'\nterraform destroy\nEOF", "iac-destroy"),
    ("cat <<EOF\nrm -rf /\nEOF", None),
    # near misses that stay allowed
    ("mkfs.ext4 --help", None),
    ("killall -0 node", None),
]

FALLBACK: list[tuple[str, str | None]] = [
    ('terraform des"troy', "iac-destroy"),
    ('dd if=x of="/dev/sda', "dd-device"),
]
