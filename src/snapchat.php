<?php

include_once dirname(__FILE__) . '/snapchat_agent.php';
include_once dirname(__FILE__) . '/snapchat_cache.php';

/**
 * @file
 *   Provides an implementation of the undocumented Snapchat API.
 */
class Snapchat extends SnapchatAgent {

	/**
	 * The media types for snaps from confirmed friends.
	 */
	const MEDIA_IMAGE = 0;
	const MEDIA_VIDEO = 1;
	const MEDIA_VIDEO_NOAUDIO = 2;

	/**
	 * The media type for a friend request (not technically media, but it
	 * shows up in the feed).
	 */
	const MEDIA_FRIEND_REQUEST = 3;

	/**
	 * The media types for snaps from unconfirmed friends.
	 */
	const MEDIA_FRIEND_REQUEST_IMAGE = 4;
	const MEDIA_FRIEND_REQUEST_VIDEO = 5;
	const MEDIA_FRIEND_REQUEST_VIDEO_NOAUDIO = 6;

	/**
	 * Snap statuses.
	 */
	const STATUS_NONE = -1;
	const STATUS_SENT = 0;
	const STATUS_DELIVERED = 1;
	const STATUS_OPENED = 2;
	const STATUS_SCREENSHOT = 3;

	/**
	 * Friend statuses.
	 */
	const FRIEND_CONFIRMED = 0;
	const FRIEND_UNCONFIRMED = 1;
	const FRIEND_BLOCKED = 2;
	const FRIEND_DELETED = 3;

	/**
	 * Privacy settings.
	 */
	const PRIVACY_EVERYONE = 0;
	const PRIVACY_FRIENDS = 1;

	/**
	 * Variables for session information.
	 */
	public $auth_token;
	public $cache;
	public $username;

	/**
	 * Sets up some initial variables. If a username and password are passed in,
	 * we attempt to log in. If a username and auth token are passed in, we'll
	 * bypass the login process and use those values.
	 *
	 * @param string $username
	 *   The username for the Snapchat account.
	 * @param string $password
	 *   The password associated with the username, if logging in.
	 * @param string $auth_token
	 *   The auth token, if already logged in.
	 */
	public function __construct($username = NULL, $password = NULL, $auth_token = NULL) {
		if (!empty($password)) {
			$this->login($username, $password);
		}
		elseif (!empty($auth_token)) {
			$this->auth_token = $auth_token;
			$this->cache = new SnapchatCache();
			$this->username = $username;
		}
	}

	/**
	 * Handles login.
	 *
	 * @param string $username
	 *   The username for the Snapchat account.
	 * @param string $password
	 *   The password associated with the username.
	 *
	 * @return mixed
	 *   The data returned by the service. Generally, returns the same
	 *   result as self::getUpdates().
	 */
	public function login($username, $password) {
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/login',
			array(
				'username' => $username,
				'password' => $password,
				'timestamp' => $timestamp,
			),
			array(
				parent::STATIC_TOKEN,
				$timestamp,
			)
		);

		if (isset($result->status) && $result->status == -100) {
			throw new Exception('Incorrect password.', 101);
		}

		if (isset($result->status) && $result->status == -101) {
			throw new Exception('No user exists with that username.', 102);
		}

		// If the login is successful, set the username and auth_token.
		if (isset($result->logged) && $result->logged) {
			$this->auth_token = $result->auth_token;
			$this->username = $result->username;

			$this->cache = new SnapchatCache();
			$this->cache->set('updates', $result);

			return $result;
		}
		else {
			throw new Exception('Login failed.', 100);
		}
	}

	/**
	 * Logs out the current user.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function logout() {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/logout',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		$this->auth_token = NULL;
		$this->cache = NULL;
		$this->username = NULL;

		if (!is_null($result)) {
			throw new Exception('Logout failed.', 110);
		}

		return TRUE;
	}

	/**
	 * Creates a user account.
	 *
	 * @param string $username
	 *   The desired username.
	 * @param string $password
	 *   The password to associate with the account.
	 * @param string $email
	 *   The email address to associate with the account.
	 * @param $birthday string
	 *   The user's birthday (yyyy-mm-dd).
	 *
	 * @return mixed
	 *   The data returned by the service. Generally, returns the same
	 *   result as calling self::getUpdates().
	 */
	public function register($username, $password, $email, $birthday) {
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/register',
			array(
				'birthday' => $birthday,
				'password' => $password,
				'email' => $email,
				'timestamp' => $timestamp,
			),
			array(
				parent::STATIC_TOKEN,
				$timestamp,
			)
		);

		if (isset($result->logged)) {
			if (isset($result->status)) {
				switch ($result->status) {
					case -200:
						throw new Exception('Invalid email address.', 121);
						break;
					case -201:
						throw new Exception('Email already associated with an address.', 122);
						break;
					case -202:
						throw new Exception('Password must be at least eight characters long.', 123);
						break;
					default:
						throw new Exception($result->message, 120);
				}
			}
		}
		else {
			throw new Exception('Registration failed.', 120);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/registeru',
			array(
				'email' => $email,
				'username' => $username,
				'timestamp' => $timestamp,
			),
			array(
				parent::STATIC_TOKEN,
				$timestamp,
			)
		);

		if (isset($result->exists) && $result->exists) {
			throw new Exception('Username already taken.', 124);
		}

		if (isset($result->message)) {
			throw new Exception($result->message, 120);
		}

		// If registration is successful, set the username and auth_token.
		if (isset($result->logged) && $result->logged) {
			$this->auth_token = $result->auth_token;
			$this->username = $result->username;

			$this->cache = new SnapchatCache();
			$this->cache->set('updates', $result);

			return $result;
		}
	}

	/**
	 * Retrieves general user, friend, and snap updates.
	 *
	 * @param bool $force
	 *   Forces an update even if there's fresh data in the cache. Defaults
	 *   to FALSE.
	 *
	 * @return struct
	 *   The data returned by the service.
	 */
	public function getUpdates($force = FALSE) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		if (!$force) {
			if ($result = $this->cache->get('updates')) {
				return $result;
			}
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/all_updates',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (empty($result->updates_response)) {
			throw new Exception('Failed to get updates.', 130);
		}

		$this->auth_token = $result->updates_response->auth_token;
		$this->cache->set('updates', $result->updates_response);
		return $result->updates_response;
	}

	/**
	 * Gets the user's snaps and formats them nicely.
	 *
	 * @return array
	 *   Snaps in a readable format.
	 */
	public function getSnaps() {
		$updates = $this->getUpdates();

		// We'll make these a little more readable.
		$snaps = array();
		foreach ($updates->snaps as $snap) {
			$snaps[] = (object) array(
				'id' => $snap->id,
				'media_id' => empty($snap->c_id) ? FALSE : $snap->c_id,
				'media_type' => $snap->m,
				'time' => empty($snap->t) ? FALSE : $snap->t,
				'sender' => empty($snap->sn) ? $this->username : $snap->sn,
				'recipient' => empty($snap->rp) ? $this->username : $snap->rp,
				'status' => $snap->st,
				'screenshot_count' => empty($snap->c) ? 0 : $snap->c,
				'sent' => $snap->sts,
				'opened' => $snap->ts,
				'broadcast' => empty($snap->broadcast) ? FALSE : (object) array(
					'url' => $snap->broadcast_url,
					'action_text' => $snap->broadcast_action_text,
					'hide_timer' => $snap->broadcast_hide_timer,
				),
			);
		}

		return $snaps;
	}

	/**
	 * Gets friends' stories.
	 *
	 * @param bool $force
	 *   Forces an update even if there's fresh data in the cache. Defaults
	 *   to FALSE.
	 *
	 * @return array
	 *   Stories.
	 */
	function getFriendStories($force = FALSE) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		if (!$force) {
			if ($result = $this->cache->get('stories')) {
				return $result;
			}
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/all_updates',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (empty($result->stories_response)) {
			throw new Exception('Failed to get updates.', 130);
		}

		$this->cache->set('stories', $result->stories_response);

		$stories = array();
		foreach ($result->stories_response->friend_stories as $group) {
			foreach ($group->stories as $story) {
				$stories[] = $story->story;
			}
		}

		return $stories;
	}

	/**
	 * Queries the friend-finding service.
	 *
	 * @param array $numbers
	 *   An array of phone numbers.
	 * @param string $country
	 *   The country code. Defaults to US.
	 *
	 * @return array
	 *   User objects.
	 */
	public function findFriends($numbers, $country = 'US') {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$numbers = array_flip($numbers);

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/find_friends',
			array(
				'countryCode' => $country,
				'numbers' => json_encode($numbers),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (!isset($result->results)) {
			throw new Exception('Could not find friends.', 140);
		}

		return $result->results;
	}

	/**
	 * Gets the user's friends.
	 *
	 * @return array
	 *   Friend objects.
	 */
	public function getFriends() {
		$updates = $this->getUpdates();

		return $updates->friends;
	}

	/**
	 * Gets the user's added friends.
	 *
	 * @return array
	 *   Friend objects.
	 */
	public function getAddedFriends() {
		$updates = $this->getUpdates();

		return $updates->added_friends;
	}

	/**
	 * Adds a friend.
	 *
	 * @param string $username
	 *   The username of the friend to add.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function addFriend($username) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'add',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		// Sigh...
		if (strpos($result->message, 'Sorry! Couldn\'t find') === 0) {
			throw new Exception('Invalid username.', 151);
		}

		return TRUE;
	}

	/**
	 * Adds multiple friends.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param array $usernames
	 *   Usernames of friends to add.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function addFriends($usernames) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$friends = array();
		foreach ($usernames as $username) {
			$friends[] = (object) array(
				'display' => '',
				'name' => $username,
				'type' => self::FRIEND_UNCONFIRMED,
			);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'multiadddelete',
				'friend' => json_encode(array(
					'friendsToAdd' => $friends,
					'friendsToDelete' => array(),
				)),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Deletes a friend.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $username
	 *   The username of the friend to delete.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function deleteFriend($username) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'delete',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Sets a friend's display name.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $username
	 *   The username of the user to modify.
	 * @param string $display
	 *   The new display name.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function setDisplayName($username, $display) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'display',
				'display' => $display,
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Blocks a user.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $username
	 *   The username of the user to be blocked.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function block($username) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'block',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Unblocks a user.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $username
	 *   The username of the user to unblock.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function unblock($username) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/friend',
			array(
				'action' => 'unblock',
				'friend' => $username,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Downloads a snap.
	 *
	 * @param string $id
	 *   The snap ID.
	 *
	 * @return data
	 *   The snap data.
	 */
	public function getMedia($id) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/blob',
			array(
				'id' => $id,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (parent::isMedia(substr($result, 0, 2))) {
			return $result;
		}
		else {
			$result = parent::decryptECB($result);

			if (parent::isMedia(substr($result, 0, 2))) {
				return $result;
			}
			else {
				throw new Exception('The media could not be decrypted.', 161);
			}
		}

		throw new Exception('The media could not be retrieved.', 160);
	}

	/**
	 * Sends event information to Snapchat.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param array $events
	 *   An array of events. This seems to be used only to report usage data.
	 * @param array $snap_info
	 *   Data to send along in addition to the event array. This is used to
	 *   mark snaps as viewed. Defaults to an empty array.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function sendEvents($events, $snap_info = array()) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/update_snaps',
			array(
				'events' => json_encode($events),
				'json' => json_encode($snap_info),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Marks a snap as viewed.
	 *
	 * Snaps can be downloaded an (apparently) unlimited amount of times before
	 * they are viewed. Once marked as viewed, they are deleted.
	 *
	 * @param string $id
	 *   The snap to mark as viewed.
	 * @param int $time
	 *   The amount of time (in seconds) the snap was viewed. Defaults to 1.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function markSnapViewed($id, $time = 1) {
		$snap_info = array(
			$id => array(
				// Here Snapchat saw fit to use time as a float instead of
				// straight milliseconds.
				't' => microtime(TRUE),
				// We add a small variation here just to make it look more
				// realistic.
				'sv' => $time + (mt_rand() / mt_getrandmax() / 10),
			),
		);

		$events = array(
			array(
				'eventName' => 'SNAP_VIEW',
				'params' => array(
					'id' => $id,
					// There are others, but it wouldn't be worth the effort to
					// put them in here since they likely don't matter.
				),
				'ts' => time() - $time,
			),
			array(
				'eventName' => 'SNAP_EXPIRED',
				'params' => array(
					'id' => $id,
				),
				'ts' => time()
			),
		);

		return $this->sendEvents($events, $snap_info);
	}

	/**
	 * Sends a screenshot event.
	 *
	 * @param string $id
	 *   The snap to mark as shot.
	 * @param int $time
	 *   The amount of time (in seconds) the snap was viewed. Defaults to 1.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function markSnapShot($id, $time = 1) {
		$snap_info = array(
			$id => array(
				// We use the same time values as in markSnapViewed, but add in the
				// screenshot status.
				't' => microtime(TRUE),
				'sv' => $time + (mt_rand() / mt_getrandmax() / 10),
				'c' => self::STATUS_SCREENSHOT,
			),
		);

		$events = array(
			array(
				'eventName' => 'SNAP_SCREENSHOT',
				'params' => array(
					'id' => $id,
				),
				'ts' => time() - $time,
			),
		);

		return $this->sendEvents($events, $snap_info);
	}

	/**
	 * Uploads a snap.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @todo
	 *   Fix media ID generation; it looks like they're GUIDs now.
	 *
	 * @param int $type
	 *   The media type, i.e. MEDIA_IMAGE or MEDIA_VIDEO.
	 * @param data $data
	 *   The file data to upload.
	 *
	 * @return mixed
	 *   The ID of the uploaded media.
	 */
	public function upload($type, $data) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		// To make cURL happy, we write the data to a file first.
		$temp = tempnam(sys_get_temp_dir(), 'Snap');
		file_put_contents($temp, parent::encryptECB($data));

		if (version_compare(PHP_VERSION, '5.5.0', '>=')) {
			$cfile = curl_file_create($temp, ($type == self::MEDIA_IMAGE ? 'image/jpeg' : 'video/quicktime'), 'snap');
		}

		$media_id = strtoupper($this->username) . '~' . time();
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/upload',
			array(
				'media_id' => $media_id,
				'type' => $type,
				'data' => (version_compare(PHP_VERSION, '5.5.0', '>=') ? $cfile : '@' . $temp . ';filename=data'),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			),
			TRUE
		);

		unlink($temp);

		return $media_id;
	}

	/**
	 * Sends a snap.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $media_id
	 *   The media ID of the snap to send.
	 * @param array $recipients
	 *   An array of recipient usernames.
	 * @param int $time
	 *   The time in seconds the snap should be available (1-10). Defaults to 3.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function send($media_id, $recipients, $time = 3) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/send',
			array(
				'media_id' => $media_id,
				'recipient' => implode(',', $recipients),
				'time' => $time,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Sets a story.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $media_id
	 *   The media ID of the story to set.
	 * @param int $media_type
	 *   The media type of the story to set (i.e. MEDIA_IMAGE or MEDIA_VIDEO).
	 * @param int $time
	 *   The time in seconds the story should be available (1-10). Defaults to 3.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function setStory($media_id, $media_type, $time = 3) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/post_story',
			array(
				'client_id' => $media_id,
				'media_id' => $media_id,
				'time' => $time,
				'timestamp' => $timestamp,
				'type' => $media_type,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Downloads a story.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $media_id
	 *   The media ID of the story.
	 * @param string $key
	 *   The base64-encoded key of the story.
	 * @param string $iv
	 *   The base64-encoded IV of the story.
	 *
	 * @return mixed
	 *   The story data or FALSE on failure.
	 */
	public function getStory($media_id, $key, $iv) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		// Retrieve encrypted story and decrypt.
		$blob = parent::get('/story_blob?story_id=' . $media_id);

		if (empty($blob)) {
			throw new Exception('Could not retrieve story blob.', 170);
		}
		
		return parent::decryptCBC($blob, $key, $iv);
	}

	/**
	 * Downloads a story's thumbnail.
	 *
	 * @param string $media_id
	 *   The media_id of the story.
	 * @param string $key
	 *   The base64-encoded key of the story.
	 * @param string $iv
	 *   The base64-encoded IV of the thumbnail.
	 *
	 * @return mixed
	 *   The thumbnail data or FALSE on failure.
	 */
	public function getStoryThumb($media_id, $key, $iv) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		// Retrieve encrypted story and decrypt.
		$blob = parent::get('/story_thumbnail?story_id=' . $media_id);

		if (empty($blob)) {
			throw new Exception('Could not retrieve thumbnail blob.', 180);
		}

		return parent::decryptCBC($blob, $key, $iv);
	}

	/**
	 * Marks a story as viewed.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @param string $id
	 *   The ID of the story.
	 * @param int $screenshot_count
	 *   Amount of times screenshotted. Defaults to 0.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function markStoryViewed($id, $screenshot_count = 0) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		// Mark story as viewed.
		$timestamp = parent::timestamp();
		$result = parent::post(
			'/update_stories',
			array(
				'friend_stories' => json_encode(array(
					array(
						'id' => $id,
						'screenshot_count' => $screenshot_count,
						'timestamp' => $timestamp,
					),
				)),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Gets the best friends and scores of the specified users.
	 *
	 * @param array $friends
	 *   An array of usernames for which to retrieve best friend information.
	 *
	 * @return struct
	 *   An dictionary of friends by username.
	 */
	public function getBests($friends) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/bests',
			array(
				'friend_usernames' => json_encode($friends),
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (empty($result)) {
			throw new Exception('Could not get best friends.', 190);
		}

		$friends = array();
		foreach((array) $result as $friend => $bests) {
			$friends[$friend] = (array) $bests;
		}

		return $friends;
	}

	/**
	 * Clears the current user's feed.
	 *
	 * @todo
	 *   Figure out what failure looks like here.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function clearFeed() {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/clear',
			array(
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		return TRUE;
	}

	/**
	 * Updates the current user's privacy setting.
	 *
	 * @param int $setting
	 *   The privacy setting, i.e. PRIVACY_EVERYONE or PRIVACY_FRIENDS.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function updatePrivacy($setting) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/settings',
			array(
				'action' => 'updatePrivacy',
				'privacySetting' => $setting,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (!(isset($result->param) && $result->param == $setting)) {
			throw new Exception('Failed to change privacy setting.', 200);
		}

		return TRUE;
	}

	/**
	 * Updates the current user's email address.
	 *
	 * @param string $email
	 *   The new email address.
	 *
	 * @return bool
	 *   TRUE if successful.
	 */
	public function updateEmail($email) {
		// Make sure we're logged in and have a valid access token.
		if (empty($this->auth_token) || empty($this->username)) {
			throw new Exception('You must be logged in.', 0);
		}

		$timestamp = parent::timestamp();
		$result = parent::post(
			'/settings',
			array(
				'action' => 'updateEmail',
				'email' => $email,
				'timestamp' => $timestamp,
				'username' => $this->username,
			),
			array(
				$this->auth_token,
				$timestamp,
			)
		);

		if (!(isset($result->param) && $result->param == $email)) {
			throw new Exception('Failed to change email address.', 210);
		}

		return TRUE;
	}

}
