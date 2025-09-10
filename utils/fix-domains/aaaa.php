<?php

namespace DNSCrypt_Proxy\acex86_co_revision;

class aaaa
{

}
$newline = "\r\n";
$Data = '\r a \r\n b \n c \n d \n e \r f '.'aaa'."\r1"."\r2"."\r3"."\r4"."\n5"."\r\n6"."\r7".'b';
$aaa = substr_count($Data, "\r");
$bbb = substr_count($Data, "\n");
echo $aaa.' : '.$bbb;
if("\r\n" === $newline)
{
    echo 'The same'.PHP_EOL;
}
$ggg = str_replace("\r\n", "\n", $Data);
$ggg = str_replace("\r", "\n", $ggg);
echo $ggg;
/*$newline = "\n";
$aaa = str_replace('\r', "\n", $Data);
$aaa = str_replace('\n', "\n", $aaa);
$aaa = str_replace('\r\n', "\n", $aaa);
echo $aaa.PHP_EOL;
$Data = preg_replace("/[^a-zA-Z0-9><@.?=:$newline\/*#_ -]/", '', $Data) ?: $Data = 'EKSERE';
echo $Data;*/