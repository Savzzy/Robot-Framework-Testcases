var esp=["null","aes126","3des","aes192","aes256"];
var ike=["sha1","sha256","sha384","sha512","aesxcbc"];
var dh= ["ecp384","ecp256","modp2048","modp1024"];
var result = [];
for (i=0;i<esp.length;i++){
    for(j=0;j<ike.length;j++){
        for(l=0;l<dh.length;l++){
            result.push(esp[i]+"-"+ike[j]+"-"+dh[l]);

        }
    }
}

console.log(result.toString());

var esp1 = null-sha1-ecp384,null - sha1 - ecp256, null - sha1 - modp2048, null - sha1 - modp1024, null - sha256 - ecp384, null - sha256 - ecp256, null - sha256 - modp2048, null - sha256 - modp1024, null - sha384 - ecp384, null - sha384 - ecp256, null - sha384 - modp2048, null - sha384 - modp1024, null - sha512 - ecp384, null - sha512 - ecp256, null - sha512 - modp2048, null - sha512 - modp1024, null - aesxcbc - ecp384, null - aesxcbc - ecp256, null - aesxcbc - modp2048, null - aesxcbc - modp1024, aes126 - sha1 - ecp384, aes126 - sha1 - ecp256, aes126 - sha1 - modp2048, aes126 - sha1 - modp1024, aes126 - sha256 - ecp384, aes126 - sha256 - ecp256, aes126 - sha256 - modp2048, aes126 - sha256 - modp1024, aes126 - sha384 - ecp384, aes126 - sha384 - ecp256, aes126 - sha384 - modp2048, aes126 - sha384 - modp1024, aes126 - sha512 - ecp384, aes126 - sha512 - ecp256, aes126 - sha512 - modp2048, aes126 - sha512 - modp1024, aes126 - aesxcbc - ecp384, aes126 - aesxcbc - ecp256, aes126 - aesxcbc - modp2048, aes126 - aesxcbc - modp1024, 3des - sha1 - ecp384, 3des - sha1 - ecp256, 3des - sha1 - modp2048, 3des - sha1 - modp1024, 3des - sha256 - ecp384, 3des - sha256 - ecp256, 3des - sha256 - modp2048, 3des - sha256 - modp1024, 3des - sha384 - ecp384, 3des - sha384 - ecp256, 3des - sha384 - modp2048, 3des - sha384 - modp1024, 3des - sha512 - ecp384, 3des - sha512 - ecp256, 3des - sha512 - modp2048, 3des - sha512 - modp1024, 3des - aesxcbc - ecp384, 3des - aesxcbc - ecp256, 3des - aesxcbc - modp2048, 3des - aesxcbc - modp1024, aes192 - sha1 - ecp384, aes192 - sha1 - ecp256, aes192 - sha1 - modp2048, aes192 - sha1 - modp1024, aes192 - sha256 - ecp384, aes192 - sha256 - ecp256, aes192 - sha256 - modp2048, aes192 - sha256 - modp1024, aes192 - sha384 - ecp384, aes192 - sha384 - ecp256, aes192 - sha384 - modp2048, aes192 - sha384 - modp1024, aes192 - sha512 - ecp384, aes192 - sha512 - ecp256, aes192 - sha512 - modp2048, aes192 - sha512 - modp1024, aes192 - aesxcbc - ecp384, aes192 - aesxcbc - ecp256, aes192 - aesxcbc - modp2048, aes192 - aesxcbc - modp1024, aes256 - sha1 - ecp384, aes256 - sha1 - ecp256, aes256 - sha1 - modp2048, aes256 - sha1 - modp1024, aes256 - sha256 - ecp384, aes256 - sha256 - ecp256, aes256 - sha256 - modp2048, aes256 - sha256 - modp1024, aes256 - sha384 - ecp384, aes256 - sha384 - ecp256, aes256 - sha384 - modp2048, aes256 - sha384 - modp1024, aes256 - sha512 - ecp384, aes256 - sha512 - ecp256, aes256 - sha512 - modp2048, aes256 - sha512 - modp1024, aes256 - aesxcbc - ecp384, aes256 - aesxcbc - ecp256, aes256 - aesxcbc - modp2048, aes256 - aesxcbc - modp1024


