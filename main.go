package main

import (
	"fmt"
	"sync"

	"github.com/aselimkaya/zephyr-release/build"
	"github.com/aselimkaya/zephyr-release/mysql"
	"github.com/ns3777k/go-shodan/shodan"
)

func main() {
	//EXAMPLE USAGES

	//[1] TAKES SHODAN RESULT FILE AS INPUT AND PRODUCES STATISTICS
	shodanISPMap, shodanDataMap, shodanVersionMap, shodanCityMap, shodanOSMap, shodanOrganizationMap := build.ProcessShodanData("SHODAN_RESULT_FILE_HERE")
	build.GetStatistics("isp", shodanISPMap)
	build.GetStatistics("data", shodanDataMap)
	build.GetStatistics("version", shodanVersionMap)
	build.GetStatistics("city", shodanCityMap)
	build.GetStatistics("os", shodanOSMap)
	build.GetStatistics("org", shodanOrganizationMap)

	//[2] SENDS QUERY TO SHODAN AND RETRIEVE RESULTS
	var hostData []*shodan.HostData = build.SendQuery2Shodan("product:MySQL country:TR", "ENTER API KEY HERE")
	var waitGroupShodanData sync.WaitGroup
	for _, data := range hostData {
		fmt.Printf("IP: %s - ISP: %s - Version: %s - City: %s - OS: %s - Organization: %s\n", data.IP.String(), data.ISP, data.Version, data.Location.City, data.OS, data.Organization)
	}
	mysql.ScanHostsByShodanData(hostData, &waitGroupShodanData)
	waitGroupShodanData.Wait()

	//[3] TAKES IP LIST AS INPUT AND SCANS SIMULTANEOUSLY
	var waitGroupIPFile sync.WaitGroup
	mysql.ScanHostsByIPFile("IP_FILE_HERE", &waitGroupIPFile)
	waitGroupIPFile.Wait()

	//[4] TAKES AN IP AND SCANS
	mysql.ScanHost("IP_HERE")
}
