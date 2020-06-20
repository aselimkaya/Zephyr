package build

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/ns3777k/go-shodan/shodan"
)

type entry struct {
	val int
	key string
}

type entries []entry

func (s entries) Len() int           { return len(s) }
func (s entries) Less(i, j int) bool { return s[i].val < s[j].val }
func (s entries) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func GetStatistics(fileName string, shodanMap map[string]int) {
	var es entries
	for k, v := range shodanMap {
		es = append(es, entry{val: v, key: k})
	}

	sort.Sort(sort.Reverse(es))

	f, err := os.OpenFile(fileName+".txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	for _, e := range es {
		fmt.Fprintf(f, "%s : %d\n", e.key, e.val)
	}
}

func ProcessShodanData(fileName string) (map[string]int, map[string]int, map[string]int, map[string]int, map[string]int, map[string]int) {
	var data shodan.HostData
	var IPList []string

	shodanISPMap := make(map[string]int)
	shodanDataMap := make(map[string]int)
	shodanVersionMap := make(map[string]int)
	shodanCityMap := make(map[string]int)
	shodanOrganizationMap := make(map[string]int)
	shodanOSMap := make(map[string]int)

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for scanner.Scan() {
		err = json.Unmarshal([]byte(scanner.Text()), &data)
		if err != nil {
			panic(err)
		} else {
			if !contains(IPList, data.IP.String()) {
				IPList = append(IPList, data.IP.String())

				if val, ok := shodanISPMap[data.ISP]; ok {
					shodanISPMap[data.ISP] = val + 1
				} else {
					shodanISPMap[data.ISP] = 1
				}

				if val, ok := shodanDataMap[data.Data]; ok {
					shodanDataMap[data.Data] = val + 1
				} else {
					shodanDataMap[data.Data] = 1
				}

				if val, ok := shodanVersionMap[string(data.Version)]; ok {
					shodanVersionMap[string(data.Version)] = val + 1
				} else {
					shodanVersionMap[string(data.Version)] = 1
				}

				if val, ok := shodanCityMap[data.Location.City]; ok {
					shodanCityMap[data.Location.City] = val + 1
				} else {
					shodanCityMap[data.Location.City] = 1
				}

				if val, ok := shodanOrganizationMap[data.Organization]; ok {
					shodanOrganizationMap[data.Organization] = val + 1
				} else {
					shodanOrganizationMap[data.Organization] = 1
				}

				if val, ok := shodanOSMap[data.OS]; ok {
					shodanOSMap[data.OS] = val + 1
				} else {
					shodanOSMap[data.OS] = 1
				}
			}
		}
	}

	return shodanISPMap, shodanDataMap, shodanVersionMap, shodanCityMap, shodanOSMap, shodanOrganizationMap
}

func SendQuery2Shodan(query, APIKey string) []*shodan.HostData {
	client := shodan.NewClient(nil, APIKey)

	var options shodan.HostQueryOptions = shodan.HostQueryOptions{
		Query: query,
	}

	hostMatch, err := client.GetHostsForQuery(context.Background(), &options)

	if err != nil {
		panic("Query Error! An error occured while retrieving data.")
	}

	return hostMatch.Matches
}
