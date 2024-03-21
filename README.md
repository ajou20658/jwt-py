# 해당 문서에서는 JWT 토큰 생성, 재갱신 및 만료 관리에 대한 API스펙을 정의합니다.
## 엔드 포인트 정리
* issue
```
유저를 식별할 수 있는 회원번호, 이름, 권한을 이용하여 jwt를 생성합니다.
Claims에 저장되는 정보는 다음과 같습니다.
'sub':회원번호
'name':이름
'auth':권한
결과는 application/json형식으로 반환됩니다.
```
* reissue
```
accessToken이 만료되고 refreshToken은 유효한 사용자에게 JWT를 갱신시켜줍니다.
'Authorizatioin'헤더에 "Bearer "+{refreshToken} 값을 포함해 요청을 보내면 application/json형식으로 반환됩니다.
```
* logout
```
accessToken이 유효한 사용자가 요청을 보내면 accessToken을 redis에 만료될 때 까지 저장합니다.
'Authorization'헤더에 "Bearer "+{accessToken} 값을 포함해 요청합니다.
```


##
