package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"gopkg.in/go-playground/webhooks.v5/github"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type GitHubStatus string
type CreateTime time.Time

const (
	Error   GitHubStatus = "error"
	Pending GitHubStatus = "pending"
	Failure GitHubStatus = "failure"
	Success GitHubStatus = "success"
)

type Build struct {
	SHA          string
	RepoFullName string
	Branch       string
	BuildLog     []string
	CreateDate   time.Time
	StartDate    time.Time
	EndDate      time.Time
	Status       GitHubStatus
	Message      string
	URL          string
}

type BuildsForSHA struct {
	SHA    string
	Builds []Build
}
type Builds struct {
	Builds []Build
}

var (
	BuildsMap     = make(map[string][]Build)
	BuildsMapTime = make(map[time.Time][]Build)
	BuildMutex    sync.Mutex
	BuildDBMutex  sync.RWMutex
)

func hashBuild(build Build) string {
	h := crypto.SHA1.New()
	io.WriteString(h, build.SHA)
	io.WriteString(h, build.CreateDate.String())
	return string(h.Sum(nil))
}

func makeBuild(SHA string, RepoFullName string, Branch string) Build {
	return Build{
		SHA:          SHA,
		RepoFullName: RepoFullName,
		CreateDate:   time.Now(),
		Branch:       Branch}
}

func replaceOrAddBuildsMapTime(build Build) {
	h := hashBuild(build)
	for i := range BuildsMapTime[build.CreateDate] {
		if h == hashBuild(BuildsMapTime[build.CreateDate][i]) {
			BuildsMapTime[build.CreateDate][i] = build
			return
		}
	}
	BuildsMapTime[build.CreateDate] = append(BuildsMapTime[build.CreateDate], build)
}

func replaceOrAddBuildsMap(build Build) {
	h := hashBuild(build)
	for i := range BuildsMap[build.SHA] {
		if h == hashBuild(BuildsMap[build.SHA][i]) {
			BuildsMap[build.SHA][i] = build
			return
		}
	}
	BuildsMap[build.SHA] = append(BuildsMap[build.SHA], build)
}

func getBuilds(SHA string) []Build {
	BuildDBMutex.RLock()
	defer BuildDBMutex.RUnlock()
	return BuildsMap[SHA]
}

type TimeSlice []time.Time

func (p TimeSlice) Len() int {
	return len(p)
}

func (p TimeSlice) Less(i, j int) bool {
	return p[i].Before(p[j])
}

func (p TimeSlice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func getBuildsDescending() []Build {
	BuildDBMutex.RLock()
	defer BuildDBMutex.RUnlock()
	var keys []time.Time
	for k := range BuildsMapTime {
		keys = append(keys, k)
	}
	sort.Sort(TimeSlice(keys))
	builds := make([]Build, 0, len(keys))
	for _, k := range keys {
		for _, b := range BuildsMapTime[k] {
			builds = append(builds, b)
		}
	}
	return builds
}

func addBuild(build Build) {
	BuildDBMutex.Lock()
	defer BuildDBMutex.Unlock()
	replaceOrAddBuildsMap(build)
	replaceOrAddBuildsMapTime(build)
	writeBuildFile(build)
}

func loadBuilds() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	path := dir + string(os.PathSeparator) + "db"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if ok, _ := regexp.MatchString("^[a-z0-9]{40}.json$", f.Name()); !f.IsDir() && ok {
			bytes, err := ioutil.ReadFile(path + string(os.PathSeparator) + f.Name())
			if err != nil {
				log.Fatal(err)
			}
			var builds []Build
			err = json.Unmarshal(bytes, &builds)
			BuildsMap[strings.TrimSuffix(f.Name(), ".json")] = builds
		}
	}
	for _, v := range BuildsMap {
		for _, b := range v {
			BuildsMapTime[b.CreateDate] = append(BuildsMapTime[b.CreateDate], b)
		}
	}
}

func writeBuildFile(build Build) {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	path := dir + string(os.PathSeparator) + "db"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 0755)
	}
	path += string(os.PathSeparator) + build.SHA + ".json"
	pathBak := path + ".bak"
	if _, err := os.Stat(path); os.IsExist(err) {
		err = os.Rename(path, pathBak)
		if err != nil {
			log.Fatal(err)
		}
	}
	json, _ := json.Marshal(BuildsMap[build.SHA])
	err = ioutil.WriteFile(path, json, 0644)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(pathBak); os.IsExist(err) {
		err = os.Remove(pathBak)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func renderTemplate(writer http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles(tmpl + ".html")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	err = t.Execute(writer, data)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}

}

func main() {
	loadBuilds()
	http.HandleFunc("/", handler);
	http.HandleFunc("/builds/", buildsHandler)
	http.HandleFunc("/build/", buildHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func buildHandler(writer http.ResponseWriter, request *http.Request) {
	sha := strings.TrimPrefix(request.URL.Path, "/build/")
	b := getBuilds(sha)
	renderTemplate(writer, "build", &BuildsForSHA{SHA:sha, Builds:b });
}

func buildsHandler(writer http.ResponseWriter, request *http.Request) {
	getBuildsDescending()
	renderTemplate(writer, "builds", &Builds{Builds:getBuildsDescending()});
}

func handler(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case "POST":
		handleWebHook(writer, request)
	case "GET":
		fallthrough
	default:
		http.Redirect(writer, request, "/builds/", http.StatusSeeOther);
	}
}

func handleWebHook(writer http.ResponseWriter, request *http.Request) {
	hook, _ := github.New()
	payload, err := hook.Parse(request, github.PushEvent, github.PullRequestEvent)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	switch payload.(type) {
	case github.PushPayload:
		push := payload.(github.PushPayload)
		for _, c := range push.Commits {
			log.Println("Create build", c.ID, push.Repository.FullName)
			go build(makeBuild(c.ID, push.Repository.FullName, strings.TrimPrefix(push.Ref, "refs/heads/")))
		}

	case github.PullRequestPayload:
		pullRequest := payload.(github.PullRequestPayload)
		if pullRequest.Action == "opened" || pullRequest.Action == "reopened" {
			log.Println("Create build", pullRequest.PullRequest.Head.Sha, pullRequest.Repository.FullName)
			go build(makeBuild(
				pullRequest.PullRequest.Head.Sha,
				pullRequest.Repository.FullName,
				pullRequest.PullRequest.Head.Ref))
		}
	}
}

func buildError(build Build, err error) {
	build.BuildLog = append(build.BuildLog, err.Error())
	build.Status = Error
	build.Message = "Error. See log"
	addBuild(build)
	postGithubStatus(build)
	log.Println(err)
}

func build(build Build) {
	builds := getBuilds(build.SHA)
	if len(builds) != 0 {
		for _, b := range builds {
			if b.Status == Success || b.Status == Failure {
				postGithubStatus(b)
				return
			}
		}
	}
	build.Status = Pending
	build.Message = "Queued Job"
	build.URL = os.Getenv("SERVER_HOME_URI") + "/build/" + build.SHA
	addBuild(build)
	postGithubStatus(build)
	{
		BuildMutex.Lock()
		defer BuildMutex.Unlock()

		build.StartDate = time.Now()

		build.Message = "Running Job"
		addBuild(build)
		postGithubStatus(build)

		cmd := exec.Command("git",
			"clone",
			"--branch="+build.Branch,
			"https://token:"+os.Getenv("MY_PERSONAL_TOKEN")+"@github.com/"+build.RepoFullName+".git",
			"repo")
		log.Println("git clone --branch="+build.Branch+
			" https://github.com/"+build.RepoFullName+".git")
		build.BuildLog = append(build.BuildLog, "git --branch="+build.Branch+
			" https://github.com/"+build.RepoFullName+".git")

		repoDir, err := os.Getwd()
		if err != nil {
			os.RemoveAll(repoDir)
			buildError(build,err)
			return
		}
		repoDir += string(os.PathSeparator) + "repo"

		out, err := cmd.Output()

		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				goto end
			}
			os.RemoveAll(repoDir)
			buildError(build,err)
			return
		}
		log.Println(string(out))
		build.BuildLog = append(build.BuildLog, strings.Split(string(out),"\n")...)

		cmd = exec.Command("git",
			"reset", "--hard", build.SHA)
		log.Println("git reset --hard " + build.SHA)
		build.BuildLog = append(build.BuildLog, "git reset --hard " + build.SHA)
		cmd.Dir = repoDir


		out, err = cmd.Output()

		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				goto end
			}
			os.RemoveAll(repoDir)
			buildError(build,err)
			return
		}
		log.Println(string(out))
		build.BuildLog = append(build.BuildLog, strings.Split(string(out),"\n")...)

		cmd = exec.Command("go",
			"build", "-v")
		log.Println("go build -v")
		build.BuildLog = append(build.BuildLog, "go build -v")
		cmd.Dir = repoDir

		out, err = cmd.Output()

		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				goto end
			}
			os.RemoveAll(repoDir)
			buildError(build,err)
			return
		}
		log.Println(string(out))
		build.BuildLog = append(build.BuildLog, strings.Split(string(out),"\n")...)

		cmd = exec.Command("go",
			"test", "-v")
		log.Println("go test -v")
		build.BuildLog = append(build.BuildLog, "go test -v")
		cmd.Dir = repoDir

		out, err = cmd.Output()

		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				goto end
			}
			os.RemoveAll(repoDir)
			buildError(build,err)
			return
		}
		log.Println(string(out))
		build.BuildLog = append(build.BuildLog, strings.Split(string(out),"\n")...)

		end:
			if _, ok := err.(*exec.ExitError); ok {
				build.Message = "Build Failure"
				build.Status = Failure
			} else {
				build.Message = "Build Success"
				build.Status = Success
			}
			build.EndDate = time.Now()
			os.RemoveAll(repoDir)
			addBuild(build)
			postGithubStatus(build)
	}

}

type GitHubStatusJSON struct {
	State       string `json:"state"`
	TargetUrl   string `json:"target_url"`
	Description string `json:"description"`
	Context     string `json:"context"`
}

func postGithubStatus(build Build) {
	url := "https://api.github.com/repos/" + build.RepoFullName + "/statuses/" + build.SHA
	body, err := json.Marshal(
		GitHubStatusJSON{
			State:       string(build.Status),
			TargetUrl:   build.URL,
			Context:     "My CI",
			Description: build.Message,
		})
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth("token", os.Getenv("MY_PERSONAL_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	httputil.DumpResponse(resp, false)
}
