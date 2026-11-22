package delivery

import (
	"sort"
	"strconv"
	"strings"
)

// maxAcceptLanguageEntries bounds the work spent on one Accept-Language header.
const maxAcceptLanguageEntries = 16

// RequestLocale returns the language a code message is written in, as the
// lower-case primary subtag of a BCP 47 tag ("ru" for "ru-RU"). The sources are
// tried in this order: explicit (a request body's "locale"), query (the
// request's "lang" query parameter, the language chosen in the client app),
// then acceptLanguage, the request's Accept-Language header, whose languages
// are tried by their q-values. A value that is not a language tag is ignored.
// When allowed is not empty, only its languages are accepted. The result is ""
// when nothing matches: the event then has no metadata.locale and
// message-delivery uses its default locale.
func RequestLocale(explicit, query, acceptLanguage string, allowed []string) string {
	for _, tag := range []string{explicit, query} {
		if language := primaryLanguage(tag); language != "" && isAllowedLocale(language, allowed) {
			return language
		}
	}
	for _, tag := range acceptedLanguages(acceptLanguage) {
		if language := primaryLanguage(tag); language != "" && isAllowedLocale(language, allowed) {
			return language
		}
	}
	return ""
}

// acceptedLanguages returns the tags of an Accept-Language header, most
// preferred first. Tags with q=0 or an invalid q-value are dropped.
func acceptedLanguages(header string) []string {
	type weighted struct {
		tag string
		q   float64
	}
	parts := strings.SplitN(header, ",", maxAcceptLanguageEntries+1)
	if len(parts) > maxAcceptLanguageEntries {
		parts = parts[:maxAcceptLanguageEntries]
	}
	entries := make([]weighted, 0, len(parts))
	for _, part := range parts {
		tag, params, _ := strings.Cut(part, ";")
		entry := weighted{tag: strings.TrimSpace(tag), q: 1}
		for _, param := range strings.Split(params, ";") {
			name, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || q < 0 || q > 1 {
				q = 0
			}
			entry.q = q
		}
		if entry.tag != "" && entry.q > 0 {
			entries = append(entries, entry)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].q > entries[j].q })
	tags := make([]string, len(entries))
	for i, entry := range entries {
		tags[i] = entry.tag
	}
	return tags
}

// primaryLanguage returns the lower-case primary language subtag of a BCP 47
// tag: two or three ASCII letters, followed by nothing or by "-" or "_" and the
// other subtags. Anything else, "*" included, gives "".
func primaryLanguage(tag string) string {
	tag = strings.TrimSpace(tag)
	end := strings.IndexAny(tag, "-_")
	if end < 0 {
		end = len(tag)
	}
	if end < 2 || end > 3 || len(tag) > 35 {
		return ""
	}
	for i := 0; i < end; i++ {
		if c := tag[i] | 0x20; c < 'a' || c > 'z' {
			return ""
		}
	}
	return strings.ToLower(tag[:end])
}

func isAllowedLocale(language string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, value := range allowed {
		if strings.EqualFold(strings.TrimSpace(value), language) {
			return true
		}
	}
	return false
}
