<?php
  include_once("semac.php");
  $pct = new semac("192.168.1.157", "2000", "2");
  $data = $pct->getSerialNumber();
  var_dump($data);

  //$data = $pct->getCurrentTimeDate();
  //var_dump($data);

  $data = $pct->getNumberOfLog();
  var_dump($data);

  $data = $pct->getAllNonRetrievedLogs();
  var_dump($data);

?>
