package base

import (
	gm "github.com/go-ginger/models"
)

type Authorization struct {
	gm.IAuthorization

	Token           string
	IsAuthenticated bool
	Roles           []string
}

func (a *Authorization) GetBase() gm.IAuthorization {
	return a
}

func (a *Authorization) Authenticated() bool {
	return a.IsAuthenticated
}

func (a *Authorization) HasRole(roles ...string) bool {
	for _, currentRole := range a.Roles {
		for _, role := range roles {
			if role == currentRole {
				return true
			}
		}
	}
	return false
}
