package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/liamg/memoryfs"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/samber/lo"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	log.Println("start")

	//results, err := localFsScan()
	//if err != nil {
	//	log.Printf("local fs scan err:%v", err)
	//	return
	//}
	//results,err := singleFileScan()
	//if err != nil {
	//	log.Printf("single fs scan err:%v", err)
	//	return
	//}
	
	//results, err := memFsScan()
	//if err != nil {
	//	log.Printf("memfs scan err.%v", err)
	//	return
	//}
	//log.Printf("results len: %v", len(results))
	
	results,err := singleK8sYamlScan()
	if err != nil {
		log.Printf("single yaml scan err:%v",err)
		return 
	}

	//misconfs := ResultsToMisconf(ftypes.Dockerfile, "DockerFile", results)
	misconfs := ResultsToMisconf(ftypes.Kubernetes, "Kubernetes", results)

	for _, misconf := range misconfs {
		sort.Sort(misconf.Successes)
		sort.Sort(misconf.Warnings)
		sort.Sort(misconf.Failures)
	}
	//log.Printf("misconf:%v", misconfs)
	//dumpMisconfs(misconfs)
	res := MisconfsToResults(misconfs)
	//log.Printf("result %+v", result)
	data, err := json.MarshalIndent(res, "", "  ")
	err = os.WriteFile("result.json", data, os.ModePerm)
	if err != nil {
		log.Printf("write result failed.%v", err)
		return
	}
	log.Printf("end")
}

func singleK8sYamlScan() (scan.Results,error) {
	scanner := kubernetes.NewScanner(options.ScannerWithEmbeddedPolicies(true))
	memfs := memoryfs.New()
	testDataPath := "./testdata/deploy.yaml"
	err := addSingleFileToMemFs(memfs, testDataPath)
	if err != nil {
		log.Printf("failed to add data files to memfs.%v", err)
		return nil, err
	}
	results, err := scanner.ScanFS(context.Background(), memfs, ".")
	if err != nil {
		log.Printf("scan fs err:%v", err)
		return nil, err
	}
	//log.Printf("yaml results:%v",results)
	return results, nil
}

func localFsScan() (scan.Results, error) {
	scanner := dockerfile.NewScanner(options.ScannerWithEmbeddedPolicies(true))
	srcFS := os.DirFS("./testdata")

	results, err := scanner.ScanFS(context.Background(), srcFS, ".")
	return results, err
}

func singleFileScan() (scan.Results,error) {
	scanner := dockerfile.NewScanner(options.ScannerWithEmbeddedPolicies(true))
	memfs := memoryfs.New()

	testDataPath := "./testdata/Dockerfile"
	err := addSingleFileToMemFs(memfs, testDataPath)
	if err != nil {
		log.Printf("failed to add data files to memfs.%v", err)
		return nil, err
	}
	results, err := scanner.ScanFS(context.Background(), memfs, ".")
	if err != nil {
		log.Printf("scan fs err:%v", err)
		return nil, err
	}
	return results, nil
}
func singleDirScan() (scan.Results,error) {
	scanner := dockerfile.NewScanner(options.ScannerWithEmbeddedPolicies(true))
	memfs := memoryfs.New()

	testDataPath, err := filepath.Abs("./testdata")
	log.Printf("test data path:%v,base %v", testDataPath, filepath.Base(testDataPath))
	err = addFilesToMemFS(memfs, false, testDataPath)
	if err != nil {
		log.Printf("failed to add data files to memfs.%v", err)
		return nil, err
	}
	results, err := scanner.ScanFS(context.Background(), memfs, filepath.Base(testDataPath))
	if err != nil {
		log.Printf("scan fs err:%v", err)
		return nil, err
	}
	return results, nil
}

func memFsScan() (scan.Results, error) {
	policiesPath, err := filepath.Abs("./rules")
	log.Printf("polic abs path:%v,base %v", policiesPath, filepath.Base(policiesPath))
	scanner := dockerfile.NewScanner(
		options.ScannerWithPolicyDirs(filepath.Base(policiesPath)),
	)

	memfs := memoryfs.New()
	err = addFilesToMemFS(memfs, true, policiesPath)
	if err != nil {
		log.Printf("failed to add policy files to memfs:%v", err)
		return nil, err
	}

	testDataPath, err := filepath.Abs("./testdata")
	log.Printf("test data path:%v,base %v", testDataPath, filepath.Base(testDataPath))
	err = addFilesToMemFS(memfs, false, testDataPath)
	if err != nil {
		log.Printf("failed to add data files to memfs.%v", err)
		return nil, err
	}
	results, err := scanner.ScanFS(context.Background(), memfs, filepath.Base(testDataPath))
	if err != nil {
		log.Printf("scan fs err:%v", err)
		return nil, err
	}
	return results, nil
}

func addSingleFileToMemFs(memfs *memoryfs.FS,fileName string) error {
	data, err := os.ReadFile(fileName)
	if err != nil {
		log.Printf("read file err %v", err)
		return err
	}
	
	baseFile := filepath.Base(fileName)
	if err := memfs.WriteFile(baseFile, data, 0o644); err != nil {
		log.Printf("failed to write file:%v",baseFile)
		return err	
	}
	return nil
}

func addFilesToMemFS(memfs *memoryfs.FS, typePolicy bool, folderName string) error {
	base := filepath.Base(folderName)
	log.Printf("add files to mem fs. base file:%v,folder name:%v",base,folderName)
	
	if err := memfs.MkdirAll(base, 0o700); err != nil {
		return err
	}
	log.Printf("memfs mkdir ok")
	
	err := filepath.Walk(filepath.FromSlash(folderName),
		func(fpath string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("walk err:%v", err)
				return err
			}
			if info.IsDir() {
				log.Printf("is dir.%v", info.Name())
				return nil
			}
			if typePolicy && !isRegoFile(info.Name()) {
				log.Printf("not rego file:%v", info.Name())
				return nil
			}
			data, err := os.ReadFile(fpath)
			if err != nil {
				log.Printf("read file err %v", err)
				return err
			}
			fileName := getFileName(fpath, info, typePolicy)
			log.Printf("write file: %v to memfs.innerPath %v,fpath %v,info %v", fileName,path.Join(base,fileName), fpath, info.Name())
			if err := memfs.WriteFile(path.Join(base, fileName), data, 0o644); err != nil {
				log.Printf("memfs write file err:%v,%v", err, fileName)
				return err
			}
			return nil
		})

	if err != nil {
		return err
	}
	return nil
}

func getFileName(fpath string, info os.FileInfo, typePolicy bool) string {
	pathParts := strings.Split(fpath, filepath.FromSlash("/"))
	fileName := info.Name()
	// append test data folder to input file name example Dockerfile.allowed_DS001
	//if len(pathParts) > 2 && !typePolicy {
	//	fileName = fmt.Sprintf("%s_%s", fileName, pathParts[len(pathParts)-2])
	//}
	log.Printf("filename %v,pathParts %v", fileName, pathParts)
	return fileName
}

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func ResultsToMisconf(configType string, scannerName string, results scan.Results) []ftypes.Misconfiguration {
	misconfs := map[string]ftypes.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().AVDID
		if result.RegoNamespace() != "" && len(result.Rule().Aliases) > 0 {
			ruleID = result.Rule().Aliases[0]
		}

		cause := NewCauseWithCode(result)

		misconfResult := ftypes.MisconfResult{
			Namespace: result.RegoNamespace(),
			Query:     query,
			Message:   flattened.Description,
			PolicyMetadata: ftypes.PolicyMetadata{
				ID:                 ruleID,
				AVDID:              result.Rule().AVDID,
				Type:               fmt.Sprintf("%s Security Check", scannerName),
				Title:              result.Rule().Summary,
				Description:        result.Rule().Explanation,
				Severity:           string(flattened.Severity),
				RecommendedActions: flattened.Resolution,
				References:         flattened.Links,
			},
			CauseMetadata: cause,
			Traces:        result.Traces(),
		}

		filePath := flattened.Location.Filename
		misconf, ok := misconfs[filePath]
		if !ok {
			misconf = ftypes.Misconfiguration{
				FileType: configType,
				FilePath: filepath.ToSlash(filePath), // defsec return OS-aware path
			}
		}

		if flattened.Warning {
			misconf.Warnings = append(misconf.Warnings, misconfResult)
		} else {
			switch flattened.Status {
			case scan.StatusPassed:
				misconf.Successes = append(misconf.Successes, misconfResult)
			case scan.StatusIgnored:
				misconf.Exceptions = append(misconf.Exceptions, misconfResult)
			case scan.StatusFailed:
				misconf.Failures = append(misconf.Failures, misconfResult)
			}
		}
		misconfs[filePath] = misconf
	}

	return ftypes.ToMisconfigurations(misconfs)
}

func NewCauseWithCode(underlying scan.Result) ftypes.CauseMetadata {
	flat := underlying.Flatten()
	cause := ftypes.CauseMetadata{
		Resource:  flat.Resource,
		Provider:  flat.RuleProvider.DisplayName(),
		Service:   flat.RuleService,
		StartLine: flat.Location.StartLine,
		EndLine:   flat.Location.EndLine,
	}
	if code, err := underlying.GetCode(); err == nil {
		cause.Code = ftypes.Code{
			Lines: lo.Map(code.Lines, func(l scan.Line, i int) ftypes.Line {
				return ftypes.Line{
					Number:      l.Number,
					Content:     l.Content,
					IsCause:     l.IsCause,
					Annotation:  l.Annotation,
					Truncated:   l.Truncated,
					Highlighted: l.Highlighted,
					FirstCause:  l.FirstCause,
					LastCause:   l.LastCause,
				}
			}),
		}
	}
	return cause
}

func dumpMisconfs(misConfs []ftypes.Misconfiguration) {
	for k, v := range misConfs {
		log.Printf("index %v, filepath %v", k, v.FilePath)
		log.Printf("dump failures:\n")
		for _, f := range v.Failures {
			log.Printf("failure. start line:%v,end line:%v,resource %v,provider %v,service %v,title %v,des %v",
				f.StartLine, f.EndLine, f.Resource, f.Provider, f.Service, f.Title, f.Description)
			for _, l := range f.Code.Lines {
				log.Printf("code line.number %v,content %v,anotation %v", l.Number, l.Content, l.Annotation)
			}
		}
	}
}

func MisconfsToResults(misconfs []ftypes.Misconfiguration) types.Results {
	var results types.Results
	for _, misconf := range misconfs {

		var detected []types.DetectedMisconfiguration

		for _, f := range misconf.Failures {
			detected = append(detected, toDetectedMisconfiguration(f, dbTypes.SeverityCritical, types.StatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Warnings {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityMedium, types.StatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Successes {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.StatusPassed, misconf.Layer))
		}
		for _, w := range misconf.Exceptions {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.StatusException, misconf.Layer))
		}

		results = append(results, types.Result{
			Target:            misconf.FilePath,
			Class:             types.ClassConfig,
			Type:              misconf.FileType,
			Misconfigurations: detected,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})

	return results
}

func toDetectedMisconfiguration(res ftypes.MisconfResult, defaultSeverity dbTypes.Severity,
	status types.MisconfStatus, layer ftypes.Layer) types.DetectedMisconfiguration {

	severity := defaultSeverity
	sev, err := dbTypes.NewSeverity(res.Severity)
	if err != nil {
		log.Printf("severity must be %s, but %s", dbTypes.SeverityNames, res.Severity)
	} else {
		severity = sev
	}

	msg := strings.TrimSpace(res.Message)
	if msg == "" {
		msg = "No issues found"
	}

	var primaryURL string

	// empty namespace implies a go rule from defsec, "builtin" refers to a built-in rego rule
	// this ensures we don't generate bad links for custom policies
	if res.Namespace == "" || strings.HasPrefix(res.Namespace, "builtin.") {
		primaryURL = fmt.Sprintf("https://avd.aquasec.com/misconfig/%s", strings.ToLower(res.ID))
		res.References = append(res.References, primaryURL)
	}

	if len(primaryURL) == 0 && len(res.References) > 0 {
		primaryURL = res.References[0]
	}

	return types.DetectedMisconfiguration{
		ID:          res.ID,
		AVDID:       res.AVDID,
		Type:        res.Type,
		Title:       res.Title,
		Description: res.Description,
		Message:     msg,
		Resolution:  res.RecommendedActions,
		Namespace:   res.Namespace,
		Query:       res.Query,
		Severity:    severity.String(),
		PrimaryURL:  primaryURL,
		References:  res.References,
		Status:      status,
		Layer:       layer,
		Traces:      res.Traces,
		CauseMetadata: ftypes.CauseMetadata{
			Resource:  res.Resource,
			Provider:  res.Provider,
			Service:   res.Service,
			StartLine: res.StartLine,
			EndLine:   res.EndLine,
			Code:      res.Code,
		},
	}
}

