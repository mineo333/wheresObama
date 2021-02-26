package main
import "fmt"
import "net/http"
import "io/ioutil"
import "time"
import "math/rand"
import "encoding/base64"
import "crypto/hmac"
import "crypto/sha1"
import "sort"
import "encoding/json"
import "strings"
//import "strconv"
var OBAMA string = "813286" // Obama's id
var oauth_consumer_key string = "Nu8BfNwhxwQXz4kouqLKC3Ebx"
var oauth_consumer_private string = "7zfETyc2rjcqtvAdutGHiPrPCh7wvqjJqPNcTpfMiupRGbNYdK"
var oauth_token string = "720752019087208450-GXyTdpZAyq4UXNMccgixYCx1WuThptF"
var oauth_token_secret string = "qxzlGqBFT3jz1KTXHiW4knwo6aayWyR43DJ0HJm5hKn3Z"
var oauth_signature_method string = "HMAC-SHA1"
var oauth_version string = "1.0"


type RateLimit string // error type
var r RateLimit = "Rate Limit Hit"
var nf RateLimit = "Not Found"
func (r RateLimit) Error() string{
	return string(r)
}

/*
Generates timestamp based on Unix
Unix time is the amount of seconds elapsed since UTC 0:00 January 1st 1970
This metric is nessecary for OAUTH 1.0
*/

func generateTimestamp() int64{ //generate the oauth timestamp
	return time.Now().Unix()
}
func percentEncode(str string) string{
	ret := ""
	m := make(map[string]string)
	m[":"] = "%3A"
	m["/"] = "%2F"
	m["?"] = "%3F"
	m["#"] = "%23"
	m["["] = "%5B"
	m["]"] = "%5D"
	m["@"] = "%40"
	m["!"] = "%21"
	m["$"] = "%24"
	m["&"] = "%26"
	m["'"] = "%27"
	m["("] = "%28"
	m[")"] = "%29"
	m["*"] = "%2A"
	m["+"] = "%2B"
	m[","] = "%2C"
	m[";"] = "%3B"
	m["="] = "%3D"
	m["%"] = "%25"
	m[" "] = "%20"
	for i := 0; i<len(str); i++{
		if m[str[i:i+1]] != ""{
			ret = (ret + m[str[i:i+1]])

		}else{
			ret = (ret + str[i:i+1])
		}

	}

	return ret;

}
func sortVals(vals map[string]string) []string{ //returns lexographically sorted keys
	arr := make([]string, 0)
	for k := range vals{
		arr = append(arr, k)
	}
	sort.Strings(arr)

	return arr
}
func param_string(params map[string]string, sortedKeys []string) string{
	ret := ""
	for i:=0;i<len(sortedKeys);i++{

		ret = fmt.Sprintf("%s%s=%s&", ret, sortedKeys[i], params[sortedKeys[i]])
	}
	return ret[0:len(ret)-1]
}
func generateSig(twitUrl, method string, other map[string]string) (string,string,string){ //returns url params and oauth
	 params := make(map[string]string)
	 nonce := generateNonce()
	 timestamp := generateTimestamp()

	params[percentEncode("oauth_consumer_key")] = percentEncode(oauth_consumer_key)
	params[percentEncode("oauth_nonce")] = percentEncode(nonce)
	params[percentEncode("oauth_signature_method")] = percentEncode(oauth_signature_method)
	params[percentEncode("oauth_timestamp")] = percentEncode(fmt.Sprintf("%d", timestamp))
	params[percentEncode("oauth_token")] = percentEncode(oauth_token)
	params[percentEncode("oauth_version")] = percentEncode(oauth_version)
	for n, v := range other{
		params[percentEncode(n)] = percentEncode(v)

	}

	keys := sortVals(params)
	param_str := param_string(params,keys)
	//fmt.Println(param_str)

	//calculate params
	base_string := fmt.Sprintf("%s&%s&%s", percentEncode(method), percentEncode(twitUrl), percentEncode(param_str))
	//fmt.Println(base_string)
	//add other stuff
	key:=[]byte(fmt.Sprintf("%s&%s", percentEncode(oauth_consumer_private), percentEncode(oauth_token_secret)))
	h := hmac.New(sha1.New, key)
	h.Write([]byte(base_string));
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	//encrypt andreq.Header.Add("Authorization", auth) gain the sig
	return sig, nonce, fmt.Sprintf("%d", timestamp)

}

/*
*/
//nonce stuff
const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
  rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
  b := make([]byte, length)
  for i := range b {
    b[i] = charset[seededRand.Intn(len(charset))]
  }
  return string(b)
}

func generateNonce() string {
  return StringWithCharset(20, charset)
}
func generateAuth1(twitUrl, method string, other map[string]string) string{
	oauth := "OAuth "
	sig,nonce,timestamp:=generateSig(twitUrl,method,other)		//"oauth_nonce",percentEncode(nonce),"oauth_signature",percentEncode(sig),"oauth_signature_method",percentEncode(oauth_signature_method),"oauth_timestamp",percentEncode(timestamp),"oauth_token",percentEncode(oauth_token),"oauth_version",percentEncode(oauth_version))
	oauth = fmt.Sprintf("%s%s=\"%s\", %s=\"%s\", %s=\"%s\", %s=\"%s\", %s=\"%s\", %s=\"%s\", %s=\"%s\"", oauth, "oauth_consumer_key", percentEncode(oauth_consumer_key), "oauth_token",percentEncode(oauth_token), "oauth_signature_method",percentEncode(oauth_signature_method),"oauth_timestamp",percentEncode(timestamp),"oauth_nonce",percentEncode(nonce), "oauth_version",percentEncode(oauth_version), "oauth_signature",percentEncode(sig))

	return oauth

}
func getBearer() (string, error){ //username is oauth_consumer_key password is oauth_consumer_private
	base_url := "https://api.twitter.com/oauth2/token"
	method := "POST"
	basic := oauth_consumer_key +":"+oauth_consumer_private
	var authb64 string = base64.StdEncoding.EncodeToString([]byte(basic));
	authb64 = "Basic " + authb64
	body_string := "grant_type=client_credentials"
	body := strings.NewReader(body_string)
	req,_ := http.NewRequest(method, base_url, body)
	req.Header.Add("Authorization",authb64)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil{
		return "", r  //error
	}
	body_resp, _ := ioutil.ReadAll(resp.Body)
	var json_data interface{} //store unmarshal there
	err = json.Unmarshal(body_resp, &json_data)
	//fmt.Printf("%s", body_resp)
	if err != nil {
		return "", r
	}
	 access_token, ok := (json_data.(map[string]interface{}))["access_token"].(string)
	 if(!ok){
		 return "", r //rate limit has been hit
	 }
	//fmt.Printf("%s", access_token)
	return access_token, nil
}





//Everything Between this comment and the OAuth1.0 comment is the OAuth 2.0 stuff
func getID2 (handle string ) (string, error){ //this is the getHandle method for Twitter API 2.0
	 base_url := "https://api.twitter.com/2/users/by/username/" + handle
	 access_token, err := getBearer()
	 if err != nil{
		 return "", r
	 }
	 oauth2_string := "Bearer " + access_token
	 method := "GET"
	 req, _ := http.NewRequest(method, base_url, nil)
	 req.Header.Add("Authorization",oauth2_string)
	 resp, err := http.DefaultClient.Do(req)
	 if err != nil{
		 return "", r
	 }
	 body_resp, _ := ioutil.ReadAll(resp.Body)
		var json_data interface{}
		err = json.Unmarshal(body_resp, &json_data)
	//	fmt.Printf("%s", body_resp)
		//id, ok := json_data.(map[string]interface{})["data"].(map[string]interface{})["id"].(string)

	 return parseGetID2(json_data)
}
func parseGetID2(json_data interface{}) (string, error){
	level1, ok1 := json_data.(map[string]interface{})
	if !ok1{
		 return "", r
	}
	level2, ok2 := level1["data"].(map[string]interface{})
	if !ok2{
		 return "", r
	}
	handle, ok3 := level2["id"].(string)
	if !ok3{
		 return "", r
	}
	return handle, nil
}


func getHandle2(id string) (string,error){ //test id: 147039284 -> Asmongold
	base_url := "https://api.twitter.com/2/users/" + id
	access_token,err := getBearer()
	if err != nil{
		return "", r
	}
	oauth2_string := "Bearer " + access_token
	method := "GET"
	req, _ := http.NewRequest(method, base_url, nil)
	 req.Header.Add("Authorization",oauth2_string)
	 resp, err := http.DefaultClient.Do(req)
	 if err != nil{
		 return "",r
	 }
	 body_resp, _ := ioutil.ReadAll(resp.Body)
		var json_data interface{}
		err = json.Unmarshal(body_resp, &json_data)
		if err != nil{
			return "", r
		}
		return parseGetHandle2(json_data)

}

func parseGetHandle2(json_data interface{}) (string, error){
	level1, ok1 := json_data.(map[string]interface{})
	if !ok1{
		 return "", r
	}
	level2, ok2 := level1["data"].(map[string]interface{})
	if !ok2{
		 return "", r
	}
	handle, ok3 := level2["username"].(string)
	if !ok3{
		 return "", r
	}
	return handle, nil
}

func getFollows2(id string) ([]string,error){
	base_url := "https://api.twitter.com/2/users/"+id+"/following"
	access_token, err := getBearer()
	if err != nil{

		return nil, r
	}
	oauth2_string := "Bearer " + access_token
	method := "GET"
	req, _ := http.NewRequest(method, base_url, nil)
	req.Header.Add("Authorization",oauth2_string)
	resp, err := http.DefaultClient.Do(req)

	if err != nil{
		return nil,r

	}
	body_resp, _ := ioutil.ReadAll(resp.Body)
	var json_data interface{}
	err = json.Unmarshal(body_resp, &json_data)
	if err != nil{
		return nil, r
	}


	return parseFollows2(json_data, resp.StatusCode)
}

func parseFollows2(json_data interface{}, StatusCode int) ([]string, error){
	ret := make([]string, 0)
		level1, ok1 := json_data.(map[string]interface{})

		if !ok1{ //rate limit
			if StatusCode == 404{
				return nil, nf
			}
			return nil, r
		}


		data_arr, ok2 := level1["data"].([]interface{})


		if !ok2{ //rate limit
			if StatusCode == 404{
				return nil, nf
			}
			return nil, r
		}



		for _,v:= range data_arr{
			ret = append(ret, v.(map[string]interface{})["id"].(string))
		}
	return ret, nil



}





func getID(handle string) string{ //This is for the now deprecated 1.1 Twitter API
	base_url := "https://api.twitter.com/1.1/users/lookup.json"
	method := "GET"
	params := make(map[string]string)
	params["screen_name"] = handle
	auth := generateAuth1(base_url, method, params)
	url := base_url + "?" + "screen_name="+handle
	req, _ := http.NewRequest(method, url, nil)
	req.Header.Add("Authorization", auth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	var json_data interface{}
	json.Unmarshal(body, &json_data)
	id, ok := ((json_data.([]interface{}))[0].(map[string]interface{}))["id_str"] //if this type asseriton goes wrong then lmao
	if !ok{ //ok not lmao return nothing. Something messed up when sending the req.
		return ""
	}
	//m0 := m[0].(map[string]interface{})
	return id.(string)

}
func getHandle(id string) string{ //This is for the now deprecated 1.1 Twitter API
	base_url := "https://api.twitter.com/1.1/users/lookup.json"
	method := "GET"
	params := make(map[string]string)
	params["user_id"] = id
	auth := generateAuth1(base_url, method, params)
	url := base_url + "?" + "user_id="+id
	req, _ := http.NewRequest(method, url, nil)
	req.Header.Add("Authorization", auth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	var json_data interface{}
	json.Unmarshal(body, &json_data)
	handle, ok := ((json_data.([]interface{}))[0].(map[string]interface{}))["screen_name"]
	if !ok {
		return ""
	}
	return handle.(string)
}
func getFollowers(id string) []string{ //only the first page
	base_url := "https://api.twitter.com/1.1/friends/ids.json"
	method := "GET"
	params := make(map[string]string)
	params["user_id"] = id
	auth := generateAuth1(base_url, method, params)
	url := base_url + "?" + "user_id="+id
	req, _ := http.NewRequest(method, url, nil)
	req.Header.Add("Authorization", auth)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)


	var json_data interface{}
	json.Unmarshal(body, &json_data)
	ids, ok := ((json_data.(map[string]interface{})["ids"]).([]interface{}))
	ret := make([]string,0)
	if !ok{
		return ret
	}
	for _, v:=range ids{
		ret = append(ret,fmt.Sprintf("%d",int64(v.(float64))))
	}
	return ret

}

func checkVisited(visited []string, id string) bool{
	for _,v := range visited{
		if id == v{
			return true
		}
	}
	return false
}
/*
Algorithm:
3 slices: Checking, To Be Pulled, Visited
-Initial peron's followers will be put in checking
-Sequentially go through checking. If not obama move to to be pulled
-If Obama is not found at all in checking, pull all from first to be pulled and then repeat process
*/
func wheresObama(handle string){ //start is a handle

	levels := 0
	checking := getFollowers(getID(handle))
	pull := make([]string, 0)
	visited := make([]string, 0)
	for 1 == 1{
		for len(checking) == 0{
			if len(pull) != 0{ //make sure we haven't already visited it and that pull is not empty. The reason we need to check again is because this a queue and it lands up at the bottom.
				if !checkVisited(visited, pull[0]){
					checking = getFollowers(pull[0])

					visited =  append(visited, pull[0])
					pull = pull[1:]
					levels++;
				}else{
					pull = pull[1:]
				}
			}else{
				fmt.Println("Could not find Obama within the rate limit")
				return; //we are out of users pull and checking so there are no more to do
			}
		}
		if /*!checkVisited(visited, checking[0]) &&*/checking[0] != OBAMA{ //is it obama????
			pull = append(pull, checking[0])
			checking = checking[1:]

		}else{ // it is obama!
			fmt.Println("Obama is", levels, "levels away!")
			return;
		}


	}

}
/*
Optimization:
Due to the rate limit, I have implemented a edited version of BFS

Pull means to get the people the person follows
*/
func wheresObama2(id string){ //start is a handle

	levels := 0
	var checking []string
	var getFollowsTemp []string
	var err error
	pull := make([]string, 0) //stuff we need to pull
	visited := make([]string, 0) //people we've visited already
	/*id, err := getID2(handle)
	if err != nil{
			fmt.Println("Could not find Obama within the rate limit")
		return;
	}*/
	checking , err = getFollows2(id) //person we are checking, start with our input handle
	if err != nil{
			fmt.Println("Could not find Obama within the rate limit")
		return;
	}
	//fmt.Println("got here")
	for true{ //infinite for loop
	//	for len(checking) == 0{ // This entire code block here is to keep pulling from the pull list until we get people with friends. This code block only runs once we have exhausted our pull list and is inteded to refill the checking lsit

		if len(checking) == 0 && err == nil{ //only run this block is checking is 0
			levels++
			for len(pull) != 0 { //make sure we haven't already visited it and that pull is not empty. The reason we need to check again is because this a queue and it lands up at the bottom.
				 //we shall now move onto the next level
				if !checkVisited(visited, pull[0]){ //check visited lmao
					getFollowsTemp, err = getFollows2(pull[0]) //get the followings of this person
					if err != nil{

						if err == nf{
							pull = pull[1:]
							continue
						}
						break
					}

					checking = append(checking, getFollowsTemp...)
					visited =  append(visited, pull[0]) //append to visited
					pull = pull[1:] //pop this person off the pull queue

			}else{
				pull = pull[1:] //skip this one
			}
		}
	}


	/*	for _, v:= range checking {
			fmt.Printf("%s\n",v)
		}*/

		if len(checking) == 0{
			fmt.Println("Could not find Obama within the rate limit")
			return;
		}else if checking[0] != OBAMA{ //is it obama????
			pull = append(pull, checking[0]) //this person is not obama. Put them onto the queue to be pulled
			checking = checking[1:] //pop them off the checking queue

		}else{ // it is obama!
			fmt.Println("Obama is", levels, "levels away!")
			return;
		}
	}

}


func main(){
	var handle string
	var id string
	var err error
	for true{
		fmt.Println("Please enter a valid Twitter handle: ")
		fmt.Scanln(&handle)
		id, err = getID2(handle)
		if err == nil{
			break
		}
		fmt.Println("This is not a valid Twitter handle")
	}

	wheresObama2(id)

}
