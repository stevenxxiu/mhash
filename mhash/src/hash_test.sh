#! /bin/sh

# $Id: hash_test.sh,v 1.3 2000/04/14 19:09:06 nmav Exp $

if (echo "testing\c"; echo 1,2,3) | grep c >/dev/null; then
  if (echo $ac_n testing; echo 1,2,3) | sed s/-n/xn/ | grep xn >/dev/null; then
    ac_n= ac_c='
' ac_t='    '
  else
    ac_n=-n ac_c= ac_t=
  fi
else
  ac_n= ac_c='\c' ac_t=
fi

test_hash ( ) {
	if test "$#" != "3" ; then
		echo "usage: test_hash id plain expected"
		exit 1
	fi
	
	plainlen=`echo $ac_n "$2$ac_c" | wc -c`
	
	got=`echo $ac_n "$2$ac_c" | ./driver $1 $plainlen`

	want=`echo $ac_n "$3$ac_c" | tr a-z A-Z`
	
	if test "$got" = ""; then
		echo "This algorithm($1) may not available"
	else
		if test "$got" != "$want" ; then
			echo "  -- TEST FAILED: $1 \"$2\""
			echo "got \"$got\""
			echo "but expected \"$want\""
			exit 1
		else
			echo $ac_n ".$ac_c"
		fi
	fi

}

echo $ac_n "testing CRC32 $ac_c"
test_hash 0 "checksum" 7FBEB02E
echo ""

echo $ac_n "testing CRC32B $ac_c"
test_hash 9 "checksum" 9ADF6FDE
echo ""

echo $ac_n "testing MD5 $ac_c"
test_hash 1 "" D41D8CD98F00B204E9800998ECF8427E
test_hash 1 a 0CC175B9C0F1B6A831C399E269772661
test_hash 1 abc 900150983CD24FB0D6963F7D28E17F72
test_hash 1 "message digest" F96B697D7CB7938D525A2F31AAF161D0
test_hash 1 abcdefghijklmnopqrstuvwxyz C3FCD3D76192E4007DFB496CCA67E13B
test_hash 1 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		D174AB98D277D9F5A5611C2C9F419D9F
test_hash 1 12345678901234567890123456789012345678901234567890123456789012345678901234567890 \
		57EDF4A22BE3C955AC49DA2E2107B67A
echo ""

echo $ac_n "testing SHA1 $ac_c"
test_hash 2 abc A9993E364706816ABA3E25717850C26C9CD0D89D
test_hash 2 abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq \
		84983E441C3BD26EBAAE4AA1F95129E5E54670F1
echo ""

echo $ac_n "testing HAVAL256 $ac_c"
test_hash 3 abcdefghijklmnopqrstuvwxyz \
		72FAD4BDE1DA8C8332FB60561A780E7F504F21547B98686824FC33FC796AFA76
test_hash 3 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		899397D96489281E9E76D5E65ABAB751F312E06C06C07C9C1D42ABD31BB6A404
echo 

echo $ac_n "testing HAVAL224 $ac_c"
test_hash 10 "0123456789" \
		EE345C97A58190BF0F38BF7CE890231AA5FCF9862BF8E7BEBBF76789
echo 

echo $ac_n "testing HAVAL192 $ac_c"
test_hash 11 "HAVAL" \
		8DA26DDAB4317B392B22B638998FE65B0FBE4610D345CF89
echo 

echo $ac_n "testing HAVAL160 $ac_c"
test_hash 12 "a" \
		4DA08F514A7275DBC4CECE4A347385983983A830
echo 

echo $ac_n "testing HAVAL128 $ac_c"
test_hash 13 "" \
		C68F39913F901F3DDF44C707357A7D70
echo 


echo $ac_n "testing RIPEMD160 $ac_c"
test_hash 5 "" 9c1185a5c5e9fc54612808977ee8f548b2258d31
test_hash 5 a 0bdc9d2d256b3ee9daae347be6f4dc835a467ffe
test_hash 5 abc 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
test_hash 5 "message digest" 5d0689ef49d2fae572b881b123a85ffa21595f36
test_hash 5 abcdefghijklmnopqrstuvwxyz f71c27109c692c1b56bbdceb5b9d2865b3708dbc
test_hash 5 abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq \
		12a053384a9c0c88e405a06c27dcf49ada62eb2b
test_hash 5 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
		b0e20b6e3116640286ed3a87a5713079b21f5189
echo ""


# the TIGER test program displays values in the wrong endian
echo $ac_n "testing TIGER $ac_c"
test_hash 7 "" 24F0130C63AC933216166E76B1BB925FF373DE2D49584E7A
test_hash 7 abc F258C1E88414AB2A527AB541FFC5B8BF935F7B951C132951
test_hash 7 Tiger 9F00F599072300DD276ABB38C8EB6DEC37790C116F9D2BDF
test_hash 7 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+- \
		 87FB2A9083851CF7470D2CF810E6DF9EB586445034A5A386
test_hash 7 "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789" \
		467DB80863EBCE488DF1CD1261655DE957896565975F9197
test_hash 7 "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham" \
		 0C410A042968868A1671DA5A3FD29A725EC1E457D3CDB303
test_hash 7 "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge." \
		 EBF591D5AFA655CE7F22894FF87F54AC89C811B6B0DA3193
test_hash 7 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-" \
		 00B83EB4E53440C576AC6AAEE0A7485825FD15E70A59FFE4
echo

echo $ac_n "testing GOST $ac_c"
test_hash 8 "This is message, length=32 bytes" \
		B1C466D37519B82E8319819FF32595E047A28CB6F83EFF1C6916A815A637FFFA
test_hash 8 "Suppose the original message has length = 50 bytes" \
		471ABA57A60A770D3A76130635C1FBEA4EF14DE51F78B4AE57DD893B62F55208
echo ""



echo "everything seems to be fine :-)"

exit 0
