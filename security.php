
/*
       security   by codydalton168
       
       防 POST OR  GET  隱碼攻擊

*/


//validate XML

function isValidXml($content){
    $content = trim($content);
    if (empty($content)) {
        return false;
    }
    //html go to hell!
    if (stripos($content, '<!DOCTYPE html>') !== false) {
        return false;
    }

    libxml_use_internal_errors(true);
    simplexml_load_string($content);
    $errors = libxml_get_errors();          
    libxml_clear_errors();  
    return empty($errors);
}



//判斷是否 Json  格式

function isJSON($string){
   return is_string($string) && is_array(json_decode($string, true)) && (json_last_error() == JSON_ERROR_NONE) ? true : false;
}

function secure_input($val){


	if (is_array($val)){         
		$output = array();    
		foreach ($val as $key => $data){
			$output[$key] = secure_input($data);
		}                             
		return $output;

	}else{
		//判斷是否 Json  格式將傳回空
		if(isJSON($val)){

			return '';
			
		//判斷是否 xml  格式將傳回空			
		} else if(isValidXml($val)){

			return '';
			
		//阿拉伯純數字不過濾                                          
		} else if(is_int($val)){

			return (int)$val;
		  
		//浮點數字不過濾  	  
		} else if(is_float($val)){       
		  		  
			return $val;
		   
		} else {


     			//防 sql 及  php sell
  
      			$ra1 = array('update','show table','insert into','select','fopen','file','copy','move_uploaded_file',
                           'fwrite','fputs','passthru','shell_exec','exec','system','mysql_query','mysql_unbuffered_query',
                           'mysql_select_db','mysql_drop_db','mysql_db_query','mysqli_query','mysqli_unbuffered_query',
                           'mysqli_select_db','mysqli_drop_db','mysqli_db_query','sqlite_query','sqlite_exec','sqlite_array_query','file_get_contents','file_put_contents',
                           'sqlite_unbuffered_query','phpinfo','<','php','?'.'>','../','function','passwd','etc','open_basedir','%0a',
                           '/var/www','union','load_file','outfile',"../","\'",'\/\*','|\*','\.\.\/','\.\/','%0b','substr','lower','lpad','unhex','0x','noframes');
  
                       $ra2 = array('onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy',
                              'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload',
                              'onbeforeupdate', 'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect',
                              'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag',
                               'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate',
                               'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup',
                               'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove',
                               'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste',
                               'onpropertychange', 'onreadystatechange', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit',
                               'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop',
                               'onsubmit', 'onunload','script','eval','behaviour','expression','style','class','javascript', 'vbscript','marquee','iframe',
                               'script','vbscript','alert','window.location','window.history.back','window.history.forward','window.history.go','history.go','history.back','history.forward');


                          $val = str_ireplace(array_merge($ra1, $ra2),'',$val);


                          return $val;
		}

	}
}