#!/usr/bin/php
<?php
  # Nota: esto asume que el modulo de semac esta instalado.
  require_once("semac.php");

  $devices = array(
    'direccion_ip' => '192.168.1.157'
  );
  foreach ($devices as $device) {
    echo "Procesando informacion desde ".$device['nombre']."[".
      $usersData = array();
      $pct = new semac($device['direccion_ip'], "2000", "1");
      $usersIdList = $pct->getUserIdList();
      if (! is_null($usersIdList) && ($usersIdList['usersCount'] > 0)) {
        echo "  Usuarios registrados:".implode(",",$usersIdList['ids'])."\n";
        echo "  Bajando detalle de los usuarios\n";
        foreach($usersIdList['ids'] as $id) {
          $userData = $pct->getUserData($id);
          if (! is_null($userData)) {
            echo "  Info. del usuario id=".$userData['userId'].
              " tarjeta=".$userData['cardNum']." decargada\n";
            $usersData[$id] = $userData;
          }
        }  
        $logsCount = $pct->getNumberOfLog();
        if (!is_null($logsCount)) {
          echo "  Informacion de logs: ".$logsCount['savedNumberLog']."/".
            $logsCount['maxLogCapacity']."\n";
          $logs = $pct->getAllNonRetrievedLogs();
          if (! is_null($logs)) {
            echo "  Bajando logs\n";
            echo "  Logs recuperados: ".$logs['logsCount']."\n";
            $insertedLogsCount = 0;
            if ($logs['logsCount'] > 0 ) {
              foreach($logs['logs'] as $log) {
                $timestamp = sprintf("%04d-%02d-%02d %02d:%02d:%02d", 
                  $log['year'], $log['month'], $log['day'],
                  $log['hour'], $log['min'], $log['sec']);
                $uid = $log['userId'];
                if (array_key_exists($uid, $usersData)) {
                  $deviceMacAddr = $device['id_dispositivo'];
                  $cardNum = $usersData[$uid]['cardNum'];
                  //$username = trim($usersData[$uid]['userName']);
                  if ($cardNum > 0) {
                    echo "    Log: ($cardNum, '$deviceMacAddr', '$timestamp')\n";
                    $res = pg_execute($db ,'insertLog', 
                      array(
                        $cardNum,
                        $deviceMacAddr,
                        $timestamp));
                    if ($res) { $insertedLogsCount++ ; }
                  }
                }
              }
              echo "  Logs insertados/leidos en la base de datos: ".
                "$insertedLogsCount/".$logs['logsCount']."\n";
            }
          }
        }
      }
    }
  }
  pg_close($db);

//  $data = $pct->deleteAllEntryExitLog();
//  var_dump($data);
?>
