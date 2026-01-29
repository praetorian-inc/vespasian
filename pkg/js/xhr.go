package js

// This file provides specialized XHR/fetch extraction helpers.
// The main extraction logic is in parser.go for simplicity.

// XHRPattern represents common XHR/fetch patterns we detect
type XHRPattern struct {
	Name        string
	Description string
}

// KnownXHRPatterns lists the XHR/fetch patterns we support
var KnownXHRPatterns = []XHRPattern{
	{"fetch", "Modern fetch API calls"},
	{"XMLHttpRequest", "Traditional XHR.open() calls"},
	{"axios", "Axios library (axios.get/post/etc)"},
	{"jQuery.ajax", "jQuery $.ajax() calls"},
}
