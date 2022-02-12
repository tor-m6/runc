//go:build !inno
// +build !inno

package configs

type HugepageLimit struct {
	// which type of hugepage to limit.
	Pagesize string `json:"page_size"`

	// usage limit for hugepage.
	Limit uint64 `json:"limit"`
}
