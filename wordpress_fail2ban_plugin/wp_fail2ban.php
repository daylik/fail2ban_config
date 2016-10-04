<?php
/*
 Plugin Name: !Wordpress дополнительные логи для fail2ban защиты.
 Plugin URI: http://dayl.ru
 Description: Плагин для помощи (Fail2ban на стороне сервера) защиты от подбора паролей.
 Version: 1.0
 Author: Олег Мешаев
 Author URI: http://dayl.ru
 */

 function my_login_failed_401($username) {
 
                           //### INFO: true = on || false = off;
 $set_syslog = true;       //### INFO: Писать ли логи в syslog и messages в папке /var/log/... актуально если надо со множества сайтов в один
 $set_fail_iplog = true;   //### INFO: Записывать логи в отдельный файл на ftp в папку logs или просто выше уровня сайта к которому нету доступа из интернета.
 $set_access_401 = false;
 
  //### INFO: проверка на вхождения в логине запрещённых символов в частности ковычег 
  //### INFO: можно попробовать ещё вот так "/([{}()|\\!@#$%^&*_\-`~\[\]?\/\'\".,]+)/"
  
   if(preg_match("/(['\"]+)/", $username)){
   //### INFO: если есть ковычки или те символы которые поставите в логине то логин обезопасить нейтральным текстом
     $username = "LOGIN_WRONG";
   }

   $you_ip = $_SERVER['REMOTE_ADDR'];   //### INFO: ip того кто авторизуется
  
   $date_now = new DateTime;
   $date_now->modify('+3 hours');       //### INFO: Корректировака времени для логана +3 часа
   $this_date = $date_now->format('M j H:i:s'); 
    
   if( $set_syslog ){
   
   //### INFO: файл будет находится в папке выше /logs/fail_ip.SITENAME.log
      //### для ispmanager в папку logs аккаунта на ftp
     $file = "./../../logs/fail_ip.".$_SERVER['SERVER_NAME'].".log";
     
       //### или для DirectAdmin в папку logs аккаунта на ftp
   //$file = "./../logs/fail_ip.".$_SERVER['SERVER_NAME'].".log"; 
   
       //### или просто на уровень выше корневой папки сайта на ftp
   //$file = "./../fail_ip.".$_SERVER['SERVER_NAME'].".log"; 
   
   //### ACTION: Открываем файл для получения существующего содержимого
   $current_ip = file_get_contents($file);
      
      
    
   //### ACTION: Добавляем нового человека в файл
    $current_ip .= "".$this_date." ip[".$you_ip."] login[ ".$username." ] userAgent(".$_SERVER['HTTP_USER_AGENT'].")\n";
    //### INFO: login и userAgent можно убрать целиком
     
    file_put_contents($file, $current_ip); //### INFO: Пишем содержимое обратно в файл
    }
    
    if( $set_fail_iplog ){
    
       //### INFO: Запись в SYSLOG в системные логи они дублируются в messages лог файл на сервере /var/log/messages так на linux (Debian)
       //define_syslog_variables();

       openlog($_SERVER['SERVER_NAME'], LOG_PID, LOG_LOCAL0);

       //$access_date = date("Y M j H:i:s"); //### INFO: мало ли надо время подправить)

       syslog(LOG_WARNING, "FAIL AUTH: date[$this_date] ip[$you_ip] login[ $username ] userAgent({$_SERVER['HTTP_USER_AGENT']})");
        //### INFO: login и userAgent можно убрать целиком

        closelog();
    }
    
    if( $set_access_401 ){
      status_header( 401 ); //### INFO: ошибка будет записываться в access.log с кодом 401 иногда 403 делают
    }
 }

 add_action( 'wp_login_failed', 'my_login_failed_401' );

 //### ACTION: удаление из информирования об авторизации самого логина и заменяем своим предложением.
 add_filter('login_errors', create_function('$a', "return 'Не верный логин или пароль.';"));
 //### ACTION: xmlrpc выключаем.
 add_filter('xmlrpc_enabled', '__return_false');

remove_action('wp_head', 'rsd_link');
remove_action('wp_head', 'wp_generator');

?>
