# Contributing to guac-rs

## Issue contributions

### Did you find a bug?

Open a [new issue](https://github.com/trustification/guac-rs/issues/new).
Be sure to include a title and clear description, with as much relevant information
as possible.

## Code contributions

### Fork

Fork the project [on GitHub](https://github.com/trustification/guac-rs)
and check out your copy locally.

```shell
git clone git@github.com:username/guac-rs.git
cd guac-rs
git remote add upstream https://github.com/trustification/guac-rs.git
git remote set-url --push upstream DISABLED
```

### Branch

Create a feature branch and start hacking:

```shell
git checkout -b my-contrib-branch
```

### Commit messages

Writing good commit logs is important. A commit log should describe what changed and why.

Follow these guidelines when writing one:

  1. The first line should preferably be 50 characters or less and contain a short description of the change.
  2. Keep the second line blank.
  3. Wrap all other lines at 72 columns.

Example of commit message:

```console
refactor: removes duplicated code

This change unifies the certify_good and certify_bad logic to promote 
reuse and to avoid redundancy in tests.

The body of the commit message can be several paragraphs, and
please do proper word-wrap and keep columns shorter than about
72 characters or so. That way `git log` will show things
nicely even when it is indented.
```

### Rebase to keep updated

Use `git rebase` to sync your work from time to time.

```shell
git fetch upstream
git rebase upstream/main
```

### Development cycle

Bug fixes and features should come with tests.
Before submitting a pull request, ensure that your change will pass CI.

Open a terminal and run

```shell
docker compose -f example/compose/compose-guac.yaml up --wait --wait-timeout 30
```

Then run the tests

```shell
cargo test
```

### Push

```shell
git push origin my-contrib-branch
```

Go to <https://github.com/yourusername/guac-rs> and select your feature branch.
Click the 'Pull Request' button and fill out the form.
