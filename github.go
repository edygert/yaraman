package main

import (
	git "github.com/go-git/go-git/v5"
)

func getGithubRepo(url string, dest string) error {
	var err error

	_, err = git.PlainClone(dest, false, &git.CloneOptions{
		URL: url,
	})
	// Pull if the repo already exists
	if err == git.ErrRepositoryAlreadyExists {
		var repo *git.Repository
		var worktree *git.Worktree

		repo, err = git.PlainOpen(dest)
		if err != nil {
			return err
		}
		worktree, err = repo.Worktree()
		if err != nil {
			return err
		}
		err = worktree.Pull(&git.PullOptions{RemoteName: "origin"})
		if err == git.NoErrAlreadyUpToDate {
			err = nil
		}
	}
	return err
}
