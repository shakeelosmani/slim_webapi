<?php
 
/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Shakeel Osmani
 */
 
 class DbHandler {
 
    private $conn;
 
    function __construct() {
        require_once dirname(__FILE__) . './DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }
	
	/* ------------- `users` table method ------------------ */
	
	/**
     * Creating new user
	 * @param String $email User login email id
	 * @param String $password User login password
     * @param String $name User full name
     * @param String $deviceToken
	 * @param String $deviceType
	 * @param String $profileImage
     */
	 
	 public function createUser($email, $password, $name, $deviceToken, $deviceType, $profileImage) {
		require_once 'PassHash.php';
		$response = array();
		
		// First check if user already existed in db
		
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);
			
			// Generating API key
            $api_key = $this->generateApiKey();
			
			// insert query
			$stmt = $this->conn->prepare("INSERT INTO users(user_email, user_password, user_name, user_api_key, user_device_token, user_device_type, user_profile_image) values(?, ?, ?, ?, ?, ?, ?)");
			
			$stmt-> bind_param("sssssss", $email, $password_hash, $name, $api_key, $deviceToken, $deviceType, $profileImage);
			
			$result = $stmt->execute();
 
            $stmt->close();
			
			// Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } 
		
		else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }
 
        return $response;
    }
	
	/**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
	 
	  public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT user_password FROM users WHERE user_email = ?");
 
        $stmt->bind_param("s", $email);
 
        $stmt->execute();
 
        $stmt->bind_result($user_password);
 
        $stmt->store_result();
		
		if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password
 
            $stmt->fetch();
 
            $stmt->close();
 
            if (PassHash::check_password($user_password, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();
 
            // user not existed with the email
            return FALSE;
        }
    }
	
	/**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT user_id from users WHERE user_email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
	
	/**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT user_id, user_name, user_email, user_api_key,  user_created_at FROM users WHERE user_email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }
	
	/**
	 * fetching user email by user id 
	 * @param int user_id
	 */ 
	 
	 public function getUserEmailByUserId($user_id) {
		 $stmt = $this->conn->prepare("SELECT user_email FROM users WHERE user_id = ?");
			$stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $email = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $email;
        } else {
            return NULL;
        }
	 }
	
	/**
     * Fetching user api key
     * @param Int $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT user_api_key FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $api_key = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }
	
	 /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT user_id FROM users WHERE user_api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }
	
	/**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT user_id from users WHERE user_api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
 
    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }
	
	/* ------------- `user_selfie` table method ------------------ */
	
	/**
     * Creating new selfie
     * @param Int $user_id user id to whom selfie belongs to
     * @param String $image image binary
     * @param String $latitude latitude from device
	 * @param String $longitude longitude from device
	 */
	 
	 public function createSelfie($user_id, $image, $latitude, $longitude) {
		$stmt = $this->conn->prepare("INSERT INTO user_selfie(image, latitude, longitude, user_id) VALUES(?,?,?,?)");
		$stmt->bind_param("sssi", $image, $latitude, $longitude, $user_id);
		$result = $stmt->execute();
        $stmt->close();
		
		if ($result) {
			// we were successful in storing the selfie now we need to manipulate the 'user_egg' table values
			return true;
		}
		
		else {
			// selfie failed to create
            return NULL;
		}
		
	}
	
	/**
     * Get all selfie
     * @param Int $user_id user id to whom selfie belongs to
	 */
	public function getUserSelfie($user_id) {
		$stmt = $this->conn->prepare("SELECT * FROM user_selfie WHERE user_id = ?");
		$stmt->bind_param("i", $user_id);
        $stmt->execute();
        $selfies = $stmt->get_result();
        $stmt->close();
        return $selfies;
	}
		
	/* ------------- `user_eggs` table method ------------------ */	
	
	/**
	 * Getting all eggs in wallet for a user
	 * @param Int $user_id to whom the eggs belongs
	 */
	 
	 public function createEgg($user_id) {
		$check = getTotalEggs($user_id);
		if(check > 0 ) {
			return NULL; // user already has egg so call update method
		}
		$stmt = $this->conn->prepare("INSERT INTO user_egg(eggs_in_wallet, total_eggs, remaining_eggs_for_redemption, user_id) VALUES (?,?,?,?)");
		$stmt->bind_param("iiii", 1, 1, 17, $user_id);
		$result = $stmt->execute();
		if ($result) {
			// we were successful in storing the first egg for this user now we need to manipulate the 'user_egg' table values when he takes new egg
			return EGG_CREATED_SUCCESSFULLY;
		}
		
		else {
			// selfie failed to create
            return NULL;
		}
	 }
	 
	 public function getTotalEggsInWallet($user_id) {
		$stmt = $this->conn->prepare("SELECT eggs_in_wallet from user_egg WHERE user_id = ?");
		$stmt->bind_param("i", $user_id);
        if($stmt->execute()){
			$total_eggs_in_wallet = $stmt->get_result()->fetch_assoc();
			$stmt->close();
			return $total_eggs_in_wallet;
		}
		
		else {
			return NULL;
		}
        
	 }
	 
	 public function getTotalEggs($user_id) {
		$stmt = $this->conn->prepare("SELECT total_eggs from user_egg WHERE user_id = ?");
		$stmt->bind_param("i", $user_id);
        if($stmt->execute()){
			$total_eggs = $stmt->get_result()->fetch_assoc();
			$stmt->close();
			return $total_eggs;
		}
		
		else {
			return NULL;
		}
        
	 }
	 
	 public function getRemainingEggsForRedemption($user_id) {
		$stmt = $this->conn->prepare("SELECT remaining_eggs_for_redemption FROM user_egg WHERE user_id = ?");
		$stmt->bind_param("i", $user_id);
        if($stmt->execute()){
			$remaining_eggs_for_redemption = $stmt->get_result()->fetch_assoc();
			$stmt->close();
			return $remaining_eggs_for_redemption;
		}
		
		else {
			return NULL;
		}
        
	 }
	 
	 public function updateEgg($user_id) {
		// to create egg we need to get old values and update with new one 
		$old_egg_in_wallet = getTotalEggsInWallet($user_id);
		$old_total_egg = getTotalEggs($user_id);
		$old_remaining_egg_for_redemption = getRemainingEggsForRedemption($user_id);
		
		$new_egg_in_wallet = $old_egg_in_wallet + 1;
		$new_total_egg = $old_egg_in_wallet + 1;
		$new_remaining_egg_for_redemption = $old_remaining_egg_for_redemption - 1;
		
		$stmt = $this->conn->prepare("UPDATE user_eggs ue SET ue.eggs_in_wallet = ?, ue.total_eggs = ?, ue.ramining_eggs_for_redemption = ? WHERE ue.user_id = ?");
		$stmt->bind_param("iiii",$new_egg_in_wallet, $new_total_egg, $new_remaining_egg_for_redemption, $user_id);
		$stmt->execute();
		$num_affected_rows = $stmt->affected_rows;
		$stmt->close();
		return $num_affected_rows > 0;
	 }
	 
	 /* Forgot password and retrieval methods*/
	 
	 public function forgotPassword($user_id) {
	 
	 // first lets get the users email
	 
		$stmt = $this->conn->prepare("SELECT user_email FROM users WHERE user_id = ?");
		$stmt->bind_param("i", $user_id);
		if ($stmt->execute()) {
			$email = $stmt->get_result()->fetch_assoc();
			$stmt->close();
			
			$authorization_code = mt_rand(100000, 999999);
			
			$stmt = $this->conn->prepare("INSERT INTO forgot_pass (user_id, authorization_code) VALUES (?,?)");
			$stmt->bind_param("ii",$user_id,$authorization_code);
			
			$result = $stmt->execute();
			
			if($result) {
				return $authorization_code;
			}
			
			else {
				return NULL;
			}
			
		}
		
	 }
	 
	 public function verifyAuthorization($user_id, $authorization_code) {
		$stmt = $this->conn->prepare("SELECT authorization_code FROM `forgot_pass` WHERE user_id=? ORDER BY requested_at DESC LIMIT 1");
		$stmt->bind_param("i", $user_id);
		if ($stmt->execute()) {
			$correctauthorization = $stmt->get_result()->fetch_assoc();
			$correctauthorization = $correctauthorization["authorization_code"];
			$stmt->close();
			if($authorization_code == $correctauthorization) {
					return "Authorization Successful";
			}
			else {
				return "Authorization Error";
			}
		}
		
		else {
			return NULL;
		}
	 }
	 
	 public function updatePassword($user_id, $password) {
		require_once 'PassHash.php';
		$password_hash = PassHash::hash($password);
		
		$stmt = $this->conn->prepare("UPDATE users SET user_password = ? WHERE user_id = ? ");
		$stmt->bind_param("si", $password_hash, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
	 }
	 
 }
 
