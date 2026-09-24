<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<jsp:include page="/WEB-INF/header.jsp"/>
<c:forEach items="${items}" var="i">
  <li><c:out value="${i.name}"/></li>
</c:forEach>
<c:import url="/WEB-INF/footer.jsp"/>
