package recorder

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

// RouteCoverage summarizes what the corpus holds for one route. A rule on
// a route, method and path with no coverage may never block (enforced by
// the gate in M4).
type RouteCoverage struct {
	Route          string             `json:"route"`
	Requests       int                `json:"requests"`
	BySource       map[string]int     `json:"by_source"`
	Methods        map[string]int     `json:"methods"`
	Endpoints      []EndpointCoverage `json:"endpoints"`
	FirstSeen      string             `json:"first_seen,omitempty"`
	LastSeen       string             `json:"last_seen,omitempty"`
	LearningSince  string             `json:"learning_since,omitempty"`
	LearningActive bool               `json:"learning_active"`
}

// EndpointCoverage is one method and path template.
type EndpointCoverage struct {
	Method   string         `json:"method"`
	Path     string         `json:"path"`
	Requests int            `json:"requests"`
	Statuses map[string]int `json:"statuses"` // "2xx" -> n
	Params   []string       `json:"params"`
}

// Coverage summarizes the corpus for every route that has exchanges, plus
// any route names passed in that have none.
func (r *Recorder) Coverage(ctx context.Context, routes []string) ([]RouteCoverage, error) {
	rows, err := r.st.DB.QueryContext(ctx, `SELECT route, source, method, path_template, status, params, ts
		FROM corpus_exchanges ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type epKey struct{ route, method, path string }
	byRoute := map[string]*RouteCoverage{}
	eps := map[epKey]*EndpointCoverage{}
	epParams := map[epKey]map[string]bool{}
	get := func(route string) *RouteCoverage {
		rc := byRoute[route]
		if rc == nil {
			rc = &RouteCoverage{Route: route, BySource: map[string]int{}, Methods: map[string]int{}}
			byRoute[route] = rc
		}
		return rc
	}
	for rows.Next() {
		var route, source, method, path, params, ts string
		var status int
		if err := rows.Scan(&route, &source, &method, &path, &status, &params, &ts); err != nil {
			return nil, err
		}
		rc := get(route)
		rc.Requests++
		rc.BySource[source]++
		rc.Methods[method]++
		if rc.FirstSeen == "" {
			rc.FirstSeen = ts
		}
		rc.LastSeen = ts
		k := epKey{route, method, path}
		ep := eps[k]
		if ep == nil {
			ep = &EndpointCoverage{Method: method, Path: path, Statuses: map[string]int{}}
			eps[k] = ep
			epParams[k] = map[string]bool{}
		}
		ep.Requests++
		ep.Statuses[statusClass(status)]++
		var ps []string
		_ = json.Unmarshal([]byte(params), &ps)
		for _, p := range ps {
			epParams[k][p] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, name := range routes {
		get(name)
	}
	for k, ep := range eps {
		for p := range epParams[k] {
			ep.Params = append(ep.Params, p)
		}
		sort.Strings(ep.Params)
		rc := byRoute[k.route]
		rc.Endpoints = append(rc.Endpoints, *ep)
	}
	out := make([]RouteCoverage, 0, len(byRoute))
	for _, rc := range byRoute {
		sort.Slice(rc.Endpoints, func(i, j int) bool {
			if rc.Endpoints[i].Path != rc.Endpoints[j].Path {
				return rc.Endpoints[i].Path < rc.Endpoints[j].Path
			}
			return rc.Endpoints[i].Method < rc.Endpoints[j].Method
		})
		var since string
		if err := r.st.DB.QueryRowContext(ctx, `SELECT started_at FROM route_learning WHERE route = ?`, rc.Route).Scan(&since); err == nil {
			rc.LearningSince = since
		}
		rc.LearningActive = r.Learning(ctx, rc.Route)
		out = append(out, *rc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })
	return out, nil
}

func statusClass(s int) string {
	if s < 100 || s > 599 {
		return "other"
	}
	return string(rune('0'+s/100)) + "xx"
}

// LearningEnds returns when a route's learning period ends, or the zero time
// when it has not started.
func (r *Recorder) LearningEnds(ctx context.Context, route string) time.Time {
	var since string
	if err := r.st.DB.QueryRowContext(ctx, `SELECT started_at FROM route_learning WHERE route = ?`, route).Scan(&since); err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, since)
	if err != nil {
		return time.Time{}
	}
	return t.Add(r.opt.LearningPeriod)
}
