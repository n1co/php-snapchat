<?php

class SnapchatTest extends PHPUnit_Framework_TestCase {

  const NONEXISTENT_USERNAME = '';

  private $snapchat = NULL;
  private $users = array();

  public function setUp() {
    $this->snapchat = new Snapchat();

    $this->users = array(
      1 => array(
        'name' => 'u1php5' . PHP_MINOR_VERSION,
        'pass' => '123456789',
      ),
      2 => array(
        'name'=> 'u2php5' . PHP_MINOR_VERSION,
        'pass' => '123456789',
      ),
      3 => array(
        'name'=> 'u3php5' . PHP_MINOR_VERSION,
        'pass' => '123456789',
      ),
      4 => array(
        'name'=> 'u4php5' . PHP_MINOR_VERSION,
        'pass' => '123456789',
      ),
      5 => array(
        'name'=> 'u5php5' . PHP_MINOR_VERSION,
        'pass' => '123456789',
      ),
    );
  }

  public function testInvalidUsername() {
    try {
      $this->snapchat->login(self::NONEXISTENT_USERNAME, 'foo');
    }
    catch (Exception $e) {
      $this->assertEquals(102, $e->getCode());
      return;
    }

    $this->fail('Failed to raise invalid username exception.');
  }

  public function testInvalidPassword() {
    try {
      $this->snapchat->login($this->users[1]['name'], '987654321');
    }
    catch (Exception $e) {
      $this->assertEquals(101, $e->getCode());
      return;
    }

    $this->fail('Failed to raise invalid password exception.');
  }

  public function testLoggedInWarnings() {
    $thrown = FALSE;

    try {
      $this->snapchat->logout();
    }
    catch (Exception $e) {
      $thrown = TRUE;
      $this->assertEquals(0, $e->getCode());
    }

    if (!$thrown) $this->fail('Failed to raise logged in warning on logout method.');
  }

  public function testLogin() {
    try {
      $this->snapchat->login($this->users[2]['name'], $this->users[2]['pass']);
    }
    catch (Exception $e) {
      $this->fail('Failed to log in: ' . $e->getMessage());
    }

    $this->assertInternalType('string', $this->snapchat->auth_token);
    $this->assertInstanceOf('SnapchatCache', $this->snapchat->cache);
    $this->assertEquals($this->users[2]['name'], $this->snapchat->username);
  }

}
