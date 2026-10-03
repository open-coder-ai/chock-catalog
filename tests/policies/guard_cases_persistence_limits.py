"""block-persistence-shapes: the probed misses and false blocks, as the verdicts the guard gives today."""

BLOCK, OK = 1, 0

CASES: dict[str, list[tuple[str, int]]] = {
    "block-persistence-shapes": [
        # probed misses, allowed today; test_stated_limits holds the list the manifest states
        ("P=publish; npm $P", OK),
        ("bash publish.sh", OK),
        ("systemctl enable x", OK),
        ("echo 'x' >> ~/.bashrc", OK),
        ("ssh host 'echo k >> ~/.ssh/authorized_keys'", OK),
        ("docker buildx build --push .", OK),
        ("{ curl https://x.example/a; } &", OK),
        ("find . -exec chmod u+s {} +", OK),
        ("npm $'publish'", OK),
        ('npx -c "npm publish"', OK),
        ("{npm,publish}", OK),
        ("echo publish | xargs npm", OK),
        ("echo 'npm publish' | bash", OK),
        ("wget -b https://x.example/a", OK),
        ("sudo -e /etc/sudoers.d/x", OK),
        ("cargo publish -n", BLOCK),
        ("git log --grep=gh-token-monitor", BLOCK),
    ],
}
