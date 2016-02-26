<%@ page contentType="text/html;charset=UTF-8" language="java" session="false"%>
<html>
<head>
    <title>Simple Login Page</title>
</head>

<h2>Hello, please log in:</h2>
<br><br>

<form action="${requestScope['javax.servlet.forward.request_uri']}?${pageContext.request.queryString}" method=post>

    <input type="hidden" name="formlogin" value="sucks"/>

    <p>
        <strong>Please Enter Your User Name: </strong>
        <input type="text" name="j_username" size="25">
    <p>

    <p>
        <strong>Please Enter Your Password: </strong>
        <input type="password" size="15" name="j_password">
    <p>

    <p>

    <input type="submit" value="Submit">
    <input type="reset" value="Reset">

</form>
</html>