<?php
  define("SOCKET_MAX_READ_ATTEMPTS", 2);
  define("SOCKET_SELECT_TIMEOUT_SEC", 2);
  define("SOCKET_SELECT_TIMEOUT_USEC", 0);
//  define("DEBUG_REQUEST", false);
//  define("DEBUG_RESPONSE", false);

  define("SEMAC_VERSION", "1.6");
  // estos son los codigos que usa el semac para
  // ACK, BS, STX, ETX
  // es el codigo ascii + 1
  define("ACK", 0x07);
  define("BS", 0x09);
  define("STX", 0x03);
  define("ETX", 0x04);

  //commands
  define("GET_USERID_LIST", 0x06);
  define("GET_USER_DATA", 0x08);
  define("GET_CURRENT_TIME_DATE", 0x10);
  define("GET_SERIAL_NUMBER", 0x13);
  define("GET_NUMBER_OF_LOG", 0x40);
  define("DELETE_ALL_ENTRY_EXIT_LOGS", 0x42);
  define("GET_ALL_NON_RETRIEVED_LOGS", 0x44);
 
  class semacMaps { 
    public static $USER_STATUS = array(
      1 => 'active',
      0 => 'inactive'
    );
    
    public static $USER_TYPE = array(
      0 => 'normalUser',
      1 => 'superUser',
      2 => 'visitor',
      3 => 'guardTouring',
      4 => 'defenseCard'
    );

    public static $BYPASS_TIME_ZONE_LEVEL = array(
      0 => 'None',
      1 => 'LV1',
      2 => 'LV2',
      3 => 'LV3',
      4 => 'LV4',
      5 => 'LV5',
      6 => 'LV6',
      7 => 'LV7',
      8 => 'LV8',
      9 => 'LV9',
      10 => 'LV10'
    );

    public static $EXPIRED_CHECK_STATUS = array(
      0 => 'disabled',
      1 => 'enabled'
    );

    public static $DOW = array(
      1 => 'Monday',
      2 => 'Tuesday',
      3 => 'Wednesday',
      4 => 'Thursday',
      5 => 'Friday',
      6 => 'Saturday',
      7 => 'Sunday'
    );

    public static $IN_OUT_FLAG = array(
      0x00 => 'None',
      0x01 => 'Access in',
      0x02 => 'Access out',
      0x11 => 'Access in during lock release time zone(Normal State)',
      0x12 => 'Access out during lock release time zone(Normal State)',
      0x21 => 'Access in during bypass on',
      0x22 => 'Access out during bypass on',
      0x31 => 'Access in during bypass off',
      0x32 => 'Access out during bypass off'
    );

    public static $VERIFICATION_SOURCE = array(
      0 => 'None',
      1 => 'Card',
      2 => 'Common password',
      5 => 'Card + Personal password',
      8 => 'Admin password',
      9 => 'Card + Admin password'
    );

    public static $EVENT_ALARM_CODE = array(
      0x00 => 'None',
      0x01 => 'Door open too long',
      0x02 => 'Door closed after alert',
      0x03 => 'By Pass On',
      0x04 => 'By Pass Off',
      0x05 => 'Back to Normal from By Pass',
      0x06 => 'Unauthorized User',
      0x07 => 'Unregistered User',
      0x08 => 'Deactivated User',
      0x09 => 'Expired User',
      0x0a => 'Anti Pass Back Violation',
      0x0b => 'Not Allowed Door',
      0x0c => 'Door Intruded',
      0x0d => 'Multi-Badge Violation',
      0x0e => 'Tamper Switch Breakdown',
      0x0f => 'Exit Button Pressed',
      0x10 => 'Door Normal Closed',
      0x11 => 'Duress Alarm On',
      0x12 => 'Fire Alarm On',
      0x13 => 'Defense On',
      0x14 => 'Defense Off',
      0x15 => 'Tamper Switch Closed',
      0x16 => 'Time Zone Violation',
      0x17 => 'Lock Forced Release Time Start',
      0x18 => 'Lock Forced Release Time End',
      0x19 => 'Warm Start',
      0x1a => 'Cold Start',
      0x1b => 'Backup Power',
      0x1c => 'Normal Power',
      0x1d => 'BF50 On',
      0x1e => 'BF50 Off',
      0x1f => 'Door Sensor short circuit',
      0x20 => 'Door Sensor open circuit',
      0x21 => 'Invalid Password',
      0x22 => 'Interlock Violation',
      0x23 => 'Emergency Open',
      0x24 => 'Emergency Close',
      0x25 => 'Fire Alarm Detection Enabled',
      0x26 => 'Fire Alarm Detection Disabled',
      0x27 => 'Door Normal Opened',
      0x28 => 'Turn Off Alarm Trigger Manually',
      0x29 => 'Turn Off Alarm Trigger Automatically',
      0x2a => 'IP Conflict',
      0x2b => 'Keypad is locked due to password error try',
      0x2c => 'Keypad recover',
      0x2d => 'Webpass Online',
      0x2e => 'Webpass Offline',
      0x2f => 'PulseOpenDoor',
      0x30 => 'ExitButtonShortCircuit',
      0x31 => 'ExitButtonOpenCircuit',
      0x32 => 'FireButtonShortCircuit',
      0x33 => 'FireButtonOpenCircuit',
      0x3b => 'SemacFastReg',
      0x3c => 'Fire alarm off'
    );

    public static $DELETE_ALL_ENTRY_EXIT_LOG_RESULT = array(
      0x00 => 'Successfully processed',
      0x02 => 'Unknown error has occurred',
      0x04 => 'Checksum error',
      0x05 => 'Other packet error',
      0x08 => 'Unknown command'
    );
  }

  class semacConverter { 
    function bigEndian2Int($bytesArray = array(), $from = 0 , $bytes = null) {
      $value = 0;
      if (empty($bytesArray)) {
        return $value;
      }
      if ($bytes === null) {
        $bytes = count($bytesArray);
      }
      $shiftBits = 0;
      foreach (array_reverse(array_slice($bytesArray, $from, $bytes)) as $v) {
        $value += ($v << $shiftBits);
        $shiftBits += 8;
      }
      return $value;
    }

    function array2Str($bytesArray = array(), $from = 0 , $bytes = null) {
      $str = null;
      if (empty($bytesArray)) {
        return $value;
      }
      if ($bytes === null) {
        $bytes = count($bytesArray);
      }
      foreach (array_slice($bytesArray, $from, $bytes) as $v) {
        $str .= chr($v);
      }
      return $str;
    }

    function array2ExpiredDateTime($bytesArray, $from = 0) {
      $expiredDateTime = array(
        'state' => null,
        'startYear' => null,
        'startMonth' => null,
        'startDay' => null,
        'startHour' => null,
        'startMin' => null,
        'endYear' => null,
        'endMonth' => null,
        'endDay' => null,
        'endHour' => null,
        'endMin' => null
      );

      $data = array_slice($bytesArray, $from, 11);
      if (count($data) == 11) {
        $expiredDateTime['state'] = semacMaps::$EXPIRED_CHECK_STATUS[$data[0]];
        $expiredDateTime['startYear'] = 2000 + $data[1];
        $expiredDateTime['startMonth'] = $data[2];
        $expiredDateTime['startDay'] = $data[3];
        $expiredDateTime['startHour'] = $data[4];
        $expiredDateTime['startMin'] = $data[5];
        $expiredDateTime['endYear'] = 2000 + $data[6];
        $expiredDateTime['endMonth'] = $data[7];
        $expiredDateTime['endDay'] = $data[8];
        $expiredDateTime['endHour'] = $data[9];
        $expiredDateTime['endMin'] = $data[10];
      }
      return $expiredDateTime;
    }

    function array2DateTime($bytesArray, $from = 0) {
      $dateTime = array(
        'year' => null,
        'month' => null,
        'day' => null,
        'dow' => null,
        'hour' => null,
        'min' => null,
        'sec' => null
      );

      $data = array_slice($bytesArray, $from, 7);
      if (count($data) == 7) {
        $dateTime['year'] = 2000 + $data[0];
        $dateTime['month'] = $data[1];
        $dateTime['day'] = $data[2];
        $dateTime['dow'] = semacMaps::$DOW[$data[3]];
        $dateTime['hour'] = $data[4];
        $dateTime['min'] = $data[5];
        $dateTime['sec'] = $data[6];
      }
      return $dateTime;
    }
  }

/*
  Contenedor de los datos de una respuesta
*/

  class responseData {
    public $length;
    public $tid;
    public $result;
    public $command;
    public $mac;
    public $data;
    public $checksum;
    public $error;
    public $errorString;

    public function __construct() {
      $this->length = null;
      $this->tid = null;
      $this->result = null;
      $this->command = null;
      $this->mac = null;
      $this->data = null;
      $this->checksum = null;
      $this->error = false;
      $this->errorString = null;
    }
  }

/*
  Clases que modelan las secciones del paquete
*/
  abstract class genericSection {
    protected $data;

    # es publico de momento para debug, luego dejar como protected
    #public $data;

    public function __construct($data = null) {
      $this->data = $data;
    }

    abstract public function dump();
    abstract public function byteSum();
  }

//clases para secciones planas (para codificarse)

  class plainSection extends genericSection {
    public function dump() {
      $count = 0;
      $values = unpack("C*", $this->encode());
      foreach($values as $value) {
        $count++;
        echo sprintf("%02x ", $value);
        if ($count % 8 == 0) { echo "  " ; }
        if ($count % 16 == 0) { 
          echo "\n" ;
          $count = 0;
        }
      }
      echo "\n";
    }

    public function encode() {
      return pack("C", $this->data);
    }

    public function byteSum() {
      $sum = 0;
      $data = $this->encode();
      $values = unpack("C*", $data);
      foreach ($values as $v) {
        $sum += $v;
      }
      return $sum;
    }

    function size() {
      $size = strlen($this->encode());
      return $size;
    }
  }

  class plainAckSection extends plainSection {
    public function __construct() {
      $data = ACK;
      parent::__construct($data);
    }
  }

  class plainStxSection extends plainSection {
    public function __construct() {
      $data = STX;
      parent::__construct($data);
    }
  }

  class plainEtxSection extends plainSection {
    public function __construct() {
      $data = ETX;
      parent::__construct($data);
    }
  }

  class plainLengthSection extends plainSection {
    public function encode() {
      return pack("N", $this->data);
    }
  }

  class plainTidSection extends plainSection {
    public function encode() {
      return pack("n", $this->data);
    }
  }

  class getUserDataDataSection extends plainSection {
    public function encode() {
      return pack("N", $this->data);
    }
  }



//clases con las secciones binarias (datos binarios)
// que se reciben del socket para decodificarse
  class binarySection extends genericSection {
    protected $length;

    public function __construct(&$data, $length = 1) {
      $u = unpack("C*", $data);
      if (!is_array($u)) { return ; }
      $this->length = $length;

      $myData = array_slice($u, 0, $length);
      $tail = array_slice($u, $length);

      $encode = null;
      foreach($tail as $v) {
        $encode .= pack("C",$v);
      }
      $data = $encode;

      $encode = null;
      foreach($myData as $v) {
        $encode .= pack("C",$v);
      }
      parent::__construct($encode);
    }

    public function dump() {
      $count = 0;
      $values = unpack("C*", $this->data);
      foreach($values as $value) {
        $count++;
        echo sprintf("%02x ", $value);
        if ($count % 8 == 0) { echo "  " ; }
        if ($count % 16 == 0) { 
          echo "\n" ;
          $count = 0;
        }
      }
      echo "\n";
    }

    public function decode() {
      $u = unpack("C{$this->length}", $this->data);
      if (!is_array($u)) { return null ; }
      return $u[1];
    }

    public function byteSum() {
      $values = unpack("C*", $this->data);
      $sum = 0;
      foreach ($values as $v) {
        $sum += $v;
      }
      return $sum;
    }
  }

  class binaryLengthSection extends binarySection {
    public function __construct(&$data) {;
      parent::__construct($data, 4);
    }

    public function decode() {
      $u = unpack("N", $this->data);
      return $u[1];
    }
  }

  class binaryTidSection extends binarySection {
    public function __construct(&$data) {;
      parent::__construct($data, 2);
    }

    public function decode() {
      $u = unpack("n", $this->data);
      return $u[1];
    }
  }

  class binaryMacSection extends binarySection {
    public function __construct(&$data) {;
      parent::__construct($data, 6);
    }

    public function decode() {
      $u = unpack("n", $this->data);
      if (!is_array($u)) { return null ; }
      $delim = '';
      $mac = '';
      foreach($u as $v) {
        $mac .= sprintf("$delim%02x",$v);
        $delim = ':';
      }
      return $mac;
    }
  }

  class binaryDataSection extends binarySection {
    public function __construct(&$data, $bytes) {;
      parent::__construct($data, $bytes);
      //file_put_contents("/var/tmp/rawData", $this->data);
    }

    public function decode() {
      $u = unpack("C{$this->length}", $this->data);
      if (!is_array($u)) { return null ; }
      return $u;
    }
  }

// Clases que modelan los requests

  class genericRequest {
    protected $sections = array();
 
    public function __construct($tid, $command, $dataSection = null) {
      /*
      Standard Command packet
      Section    size(bytes)
      ---------------------
      ACK        1 
      STX        1
      LENGTH     4 (bytes from ACK TO ETX)
      TID        2 (system unique id)
      COMMAND    1
      DATA       N
      CHECKSUM   1 (byte sum from ACK to DATA)
      ETX        1
      */
      // ACK + STX + LENGTH + TID + COMMAND + CHECKSUM + ETX = 11 bytes

      $dataBytes = 0;
      if (! empty($dataSection) && is_object($dataSection)) { 
        $dataBytes = $dataSection->size();
      }
      $s = &$this->sections;
      $s['ack'] = new plainAckSection();
      $s['stx'] = new plainStxSection();
      $s['length'] = new plainLengthSection(11 + $dataBytes);
      $s['tid'] = new plainTidSection($tid);
      $s['command'] = new plainSection($command);
      if (! empty($dataSection) && is_object($dataSection)) {
        $s['data'] = $dataSection;
      }
      $sum = 0;
      foreach($s as $section) {
        $sum += $section->byteSum();
      }
      $s['checksum'] = new plainSection($sum);
      $s['etx'] = new plainEtxSection();
    }

    public function packet() {
      $rawData = null;
      foreach ($this->sections as $section) {
        $rawData .= $section->encode();
      }
      return $rawData;
    }

    public function dump() {
      foreach($this->sections as $section => $obj) {
        echo "=== $section ===\n";
        $obj->dump();
      }
    }
  }

  class getSerialNumberRequest extends genericRequest {
    public function __construct($tid = 1) {
      parent::__construct($tid, GET_SERIAL_NUMBER, null);
    }
  }

  class getCurrentTimeDateRequest extends genericRequest {
    public function __construct($tid = 1) {
      parent::__construct($tid, GET_CURRENT_TIME_DATE, null);
    }
  }

  class getNumberOfLogRequest extends genericRequest {
    public function __construct($tid = 1) {
      parent::__construct($tid, GET_NUMBER_OF_LOG, null);
    }
  }

  class getAllNonRetrievedLogsRequest extends genericRequest {
    public function __construct($tid = 1) {
      parent::__construct($tid, GET_ALL_NON_RETRIEVED_LOGS, null);
    }
  }

  class getUserIdListRequest extends genericRequest {
    public function __construct($tid = 1) {
      parent::__construct($tid, GET_USERID_LIST, null);
    }
  }

  class getUserDataRequest extends genericRequest {
    public function __construct($tid = 1, $userId = 1) {
      $dataSection = new getUserDataDataSection($userId);
      parent::__construct($tid, GET_USER_DATA, $dataSection);
    }
  }

  class deleteAllEntryExitLogsRequest extends genericRequest {
    public function __construct($tid = 1) {
      parent::__construct($tid, DELETE_ALL_ENTRY_EXIT_LOGS, null);
    }
  }

# Clases para modelar las respuestas

  class genericResponse {
    protected $sections = array();
 
    public function __construct($data) {
      /*
      Standard return packet
      Section     size(bytes)
      -----------------------
      BS          1
      STX         1
      LENGTH      4 length
      TID         2
      RESULT      1
      COMMAND     1
      MAC Addr    6
      DATA        N
      CHECKSUM    1 (byte sum from BS to DATA)
      ETX         1
      */
  
      // Data N = LENGTH - 18 bytes
      
      //file_put_contents("/var/tmp/rawPacket", $data);

      $s = &$this->sections;
      $s['bs'] = new binarySection($data);
      $s['stx'] = new binarySection($data);
      $s['length'] = new binaryLengthSection($data);
      $s['tid'] = new binaryTidSection($data);
      $s['result'] = new binarySection($data);
      $s['command'] = new binarySection($data);
      $s['mac'] = new binaryMacSection($data);
      $s['data'] = new binaryDataSection($data, $s['length']->decode()-18);
      $s['checksum'] = new binarySection($data);
      $s['etx'] = new binarySection($data);
    }

    protected function calculateChecksum() {
      return (
       $this->sections['bs']->byteSum() +
       $this->sections['stx']->byteSum() +
       $this->sections['length']->byteSum() +
       $this->sections['tid']->byteSum() +
       $this->sections['result']->byteSum() +
       $this->sections['command']->byteSum() +
       $this->sections['mac']->byteSum() +
       $this->sections['data']->byteSum()) % 256;

    }

    public function verifyChecksum() {
      $dataChecksum = $this->sections['checksum']->decode();
      $computedChecksum = $this->calculateChecksum();
      if ($dataChecksum != $computedChecksum) {
        return false;
      }
      return $dataChecksum;      
    }

    public function getResponseData() {
      $responseData = new responseData();
      $responseData->length = $this->sections['length']->decode();
      $responseData->tid = $this->sections['tid']->decode();
      $responseData->result = $this->sections['result']->decode();
      $responseData->command = $this->sections['command']->decode();
      $responseData->mac = $this->sections['mac']->decode();
      $responseData->data = $this->sections['data']->decode();
      $responseData->checksum = $this->sections['checksum']->decode();
      if ($this->verifyChecksum() === false) {
        $responseData->error = true;
        $responseData->errorString = "Checksum verification failed data_sum=";
        $responseData->errorString .= $responseData->checksum." calculated_sum=";
        $responseData->errorString .= $this->calculateChecksum();
      }
      return $responseData;
    }

    public function dump() {
      foreach($this->sections as $section => $obj) {
        echo "=== $section ===\n";
        $obj->dump();
      }
    }
  }

  class getSerialNumberResponse extends genericResponse {
    public function getResponseData() {
      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $serial = sprintf("%02x%02X%02x", 
         $response->data[1],
         $response->data[2],
         $response->data[3]);
      return $serial;
    }
  }

  class getCurrentTimeDateResponse extends genericResponse {
    public function getResponseData() {
      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $dateTime = semacConverter::array2DateTime($response->data);
      return $dateTime;
    }
  }

  class getNumberOfLogResponse extends genericResponse {
    public function getResponseData() {
      $numberOfLogData = array(
         'savedNumberLog' => null,
         'maxLogCapacity' => null
      );

      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $numberOfLogData['savedNumberLog'] =
        semacConverter::bigEndian2Int($response->data, 0, 4);
      $numberOfLogData['maxLogCapacity'] = 
        semacConverter::bigEndian2Int($response->data, 4, 4);
      return $numberOfLogData;
    }
  }

  class getAllNonRetrievedLogsResponse extends genericResponse {
    public function getResponseData() {
      $nonRetrievedLogs = array(
        'logsCount' => 0,
        'logs' => array()
      );

      # son 20 bytes por log sin contar logIndex y cardId
      $logSize = 20;
      $log = array(
        'sec' => null, # 1 byte
        'min' => null, # 1 byte
        'hour' => null, # 1 byte
        'day' => null, # 1 byte
        'month' => null, # 1 byte
        'year' => null, # 1 byte
        'inOutFlag' => null, # 1 byte
        'verificationSource' => null, # 1 byte
        'eventAlarmCode' => null, # 1 byte
        'door' => null, # 1 byte
        'userId' => null, # 4 bytes

/*  No esta implementado por el pct 100
        'logIndex' => null, # 4 bytes
        'cardId' => null, # 8 bytes
*/
        'reserved1' => null, # 2 bytes
        'remoteControl' => null, # 1 byte
        'reserved2' => null # 3 bytes
      );

      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $data = $response->data;
      if (count($data) >= 24) { # al menos hay una entrada de logs
        $logsCount = semacConverter::bigEndian2Int($data, 0, 4);
        $logsData = array_slice($data, 4);
        # cantidad de datos de logs es igual a 20 * logsCount
        if ((count($logsData) / $logSize) == $logsCount) {
          $nonRetrievedLogs['logsCount'] = $logsCount;
          for($j = 0 ; $j < $logsCount ; $j++) {
            $relPos = $j * $logSize;
            $log['sec'] = $logsData[$relPos];
            $log['min'] = $logsData[$relPos+1];
            $log['hour'] = $logsData[$relPos+2];
            $log['day'] = $logsData[$relPos+3];
            $log['month'] = $logsData[$relPos+4];
            $log['year'] = 2000 + $logsData[$relPos+5];
            $log['inOutFlag'] = semacMaps::$IN_OUT_FLAG[$logsData[$relPos+6]];
            $log['verificationSource'] = 
              semacMaps::$VERIFICATION_SOURCE[$logsData[$relPos+7]];
            $log['eventAlarmCode'] = 
              semacMaps::$EVENT_ALARM_CODE[$logsData[$relPos+8]];
            $log['door'] = $logsData[$relPos+9];
            $log['userId'] = semacConverter::bigEndian2Int($logsData, $relPos+10, 4);
            $log['reserved1'] = array_slice($logsData, $relPos+14, 2);
            $log['remoteControl'] = $logsData[$relPos+16];
            $log['reserved2'] = array_slice($logsData, $relPos+17, 3);
            array_push($nonRetrievedLogs['logs'], $log);
          }
        }
      }
      return $nonRetrievedLogs;
    }
  }

  class getUserIdListResponse extends genericResponse {
    public function getResponseData() {
      $userIdList = array(
        'usersCount' => 0,
        'ids' => array()
      );

      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $data = $response->data;
      if (count($data) >= 4) { // los primeros 4 bytes indican el total de usuarios
        $usersCount = semacConverter::bigEndian2Int($data, 0, 4);

        $userIdList['usersCount'] = $usersCount;
        $userIds = array_slice($data, 4);
        if ((count($userIds) / 4) == $usersCount) { 
          // 4 bytes por cada id de usuario. Tengo un multiplo de 4 bytes
          for ($j = 0 ; $j < $usersCount ; $j++) {
            $userId = semacConverter::bigEndian2Int($userIds, $j*4, 4);
            array_push($userIdList['ids'], $userId);
          }
        }
      }
      return $userIdList;
    }
  }

  class getUserDataResponse extends genericResponse {
    public function getResponseData() {
      # total 78 bytes
      $userData = array( 
        'userId' => null, # 4 bytes
        'cardNum' => null,  # 8 bytes
        'userName' => null, # 31 bytes
        'expiredDateTime' => null, # 11 bytes
        'status' => null, # 1 byte
        'userType' => null, # 1 byte
        'group1' => null, # 1 byte
        'group2' => null, # 1 byte
        'group3' => null, # 1 byte
        'group4' => null, # 1 byte
        'bypassTimeZoneLevel' => null, # 1 byte
        'personalPassword' => null, # 8 bytes
        'reserved'  => null # 9 bytes 
      );

      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $data = $response->data;
      if (count($data) >= 78) { // tengo los datos de usuario
        # los +1 que pongo en el indice son porque el arreglo data
        # comienza en el indice 1.
        # Como los array_slice, array2Str y bigEndian2Int
        # tratan el arreglo internamente desde posicion 0 van bien las
        # sumas. Pero si accedo al $data de manera absoluta y quiero el
        # el byte X, estara en la posicion X+1.
        $userData['userId'] = semacConverter::bigEndian2Int($data, 0, 4);
        $userData['cardNum'] = semacConverter::bigEndian2Int($data, 4, 8);
        $userData['userName'] = semacConverter::array2Str($data, 12, 31);
        $userData['expiredDateTime'] = 
          semacConverter::array2ExpiredDateTime($data, 43);
        $userData['status'] = semacMaps::$USER_STATUS[$data[54+1]];
        $userData['userType'] = semacMaps::$USER_TYPE[$data[55+1]];
        $userData['group1'] = $data[56+1];
        $userData['group2'] = $data[57+1];
        $userData['group3'] = $data[58+1];
        $userData['group4'] = $data[59+1];
        $userData['bypassTimeZoneLevel'] = 
          semacMaps::$BYPASS_TIME_ZONE_LEVEL[$data[60+1]];
        $userData['personalPassword'] = semacConverter::array2Str($data, 61, 8);
        $userData['reserved'] = array_slice($data, 69, 9); # 69 + 9 => 78
      }
      return $userData;
    }
  }

  class deleteAllEntryExitLogResponse extends genericResponse {
    public function getResponseData() {
      $deleteResult = array(
        'result' => null,
        'status' => null
      );
      $response = parent::getResponseData();
      if ($response->error == true) {
        fwrite(STDERR, $response->errorString."\n");
        return null;
      }
      $deleteResult['result'] = $response->result;
      $deleteResult['status'] = 
        semacMaps::$DELETE_ALL_ENTRY_EXIT_LOG_RESULT[$response->result];
      return $deleteResult;
    }
  }

  class semac {
    public $terminalId;
    public $addr; 
    public $port;

    public $lastCommandPacket;
    public $lastResponsePacket;

    private $socket;

    private function __connect() {
      $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
      if ($this->socket === false) {
        return -1;
      }
      socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO,
        array('sec' => 5, 'usec' => 0));

      $cx = socket_connect($this->socket, $this->addr, $this->port);
      if ($cx === false) {
        return -2;
      }
      socket_set_nonblock($this->socket);
      return 1;
    }

    private function __sendPacket($packet) {
      $status = $this->__connect();
      if ($status > 0) { 
        $len = strlen($packet);
        $written = socket_write($this->socket, $packet);
        $this->lastCommandPacket = $packet;
        sleep(1);
      } else {
        fwrite(STDERR, "Error creating socket\n");
      }
      return $status;
    }

    private function __readResponse() {
      $buffer = null;
      $readAttempts = 0;
      $rsocks[] = $this->socket;
      $wsocks = null;
      $esocks = null;
      while ($readAttempts < SOCKET_MAX_READ_ATTEMPTS) {
//        fwrite(STDOUT, "Select intento $readAttempts\n");
        $res = socket_select($rsocks, $wsocks, $esocks, 
          SOCKET_SELECT_TIMEOUT_SEC,
          SOCKET_SELECT_TIMEOUT_USEC);
        if ($res == false) {
//          fwrite(STDERR, "socket_select timeout, intento $readAttempts\n");
          $readAttempts++;
        } else {
          if (in_array($this->socket, $rsocks)) {
            $dataSlice = null;
            $bytes = socket_recv($this->socket, $dataSlice, 2000, 0);
            while ( $bytes != 0) {
              $buffer .= $dataSlice;
//              fwrite(STDOUT, "Se leyeron $bytes bytes\n");
              $bytes = socket_recv($this->socket, $dataSlice, 2000, 0);
//              fwrite(STDOUT, "Se resetea el contador de intentos\n");
              $readAttempts=0;
            }
          }
          $readAttempts++;
        }
        $rsocks[] = $this->socket;
      }
      socket_close($this->socket);      
      $this->lastResponsePacket = $buffer;
      return $buffer;
    }

    public function __construct($addr = "192.168.1.157", 
                       $port = "2000", 
                       $terminalId = 2) {
      $this->terminalId = $terminalId;
      $this->addr = $addr;
      $this->port = $port;
      $this->lastCommandPacket = null;
      $this->lastResponsePacket = null;
    }

    public function getSerialNumber() {
      $serial = null;
      $request = new getSerialNumberRequest($this->terminalId);
      $packet = $request->packet();
      //$request->dump();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new getSerialNumberResponse($rawResponse);
          $serial = $response->getResponseData();
          //$response->dump();
        } 
      }
      return $serial;
    }

    public function getCurrentTimeDate() {
      $dateTime = null;
      $request = new getCurrentTimeDateRequest($this->terminalId);
      $packet = $request->packet();
      //$request->dump();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new getCurrentTimeDateResponse($rawResponse);
          $dateTime = $response->getResponseData();
          //$response->dump();
        } 
      }
      return $dateTime;
    }

    public function getNumberOfLog() {
      $numberOfLog = null;
      $request = new getNumberOfLogRequest($this->terminalId);
      $packet = $request->packet();
      //$request->dump();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new getNumberOfLogResponse($rawResponse);
          $numberOfLog = $response->getResponseData();
          //$response->dump();
        } 
      }
      return $numberOfLog;
    }

    public function getAllNonRetrievedLogs() {
      $logs = null;
      $request = new getAllNonRetrievedLogsRequest($this->terminalId);
      $packet = $request->packet();
      //$request->dump();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new getAllNonRetrievedLogsResponse($rawResponse);
          $logs = $response->getResponseData();
          //$response->dump();
        } 
      }
      return $logs;
    }

    public function getUserIdList() {
      $userIdList = null;
      $request = new getUserIdListRequest($this->terminalId);
      //$request->dump();
      $packet = $request->packet();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new getUserIdListResponse($rawResponse);
          //$response->dump();
          $userIdList = $response->getResponseData();
        }
      }
      return $userIdList;
    }

    public function getUserData($userId) {
      $userData = null;
      $request = new getUserDataRequest($this->terminalId, $userId);
      //$request->dump();
      $packet = $request->packet();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new getUserDataResponse($rawResponse);
          //$response->dump();
          $userData = $response->getResponseData();
        }
      }
      return $userData;
    }

    public function deleteAllEntryExitLog() {
      $deleteResult = null;
      $request = new deleteAllEntryExitLogsRequest($this->terminalId);
      //$request->dump();
      $packet = $request->packet();
      $status = $this->__sendPacket($packet);
      if ($status) {
        $rawResponse = $this->__readResponse();
        if (! empty($rawResponse)) {
          $response = new deleteAllEntryExitLogResponse($rawResponse);
          //$response->dump();
          $deleteResult = $response->getResponseData();
        }
      }
      return $deleteResult;
    }
  }

?>
