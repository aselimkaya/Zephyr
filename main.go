package main

import (
	"sync"

	"github.com/aselimkaya/zephyr-release/mysql"
	"github.com/aselimkaya/zephyr/build"
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

	//[2] TAKES IP LIST AS INPUT AND SCANS SIMULTANEOUSLY
	var waitGroup sync.WaitGroup
	mysql.ScanHosts("IP_FILE_HERE", &waitGroup)
	waitGroup.Wait()

	//[3] TAKES AN IP AND SCANS
	mysql.ScanHost("IP_HERE")
}
