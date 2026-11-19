<%@page session="false" contentType="text/html;charset=UTF-8" language="java"%>
<%@taglib prefix="c" uri="jakarta.tags.core"%>
<%@taglib prefix="e" uri="owasp.encoder.jakarta"%>
<!DOCTYPE html>
<html>
    <head>
        <title>View Items</title>
        <link href="<c:url value="/css/common.css"/>" rel="stylesheet" type="text/css">
    </head>
    <body>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <c:forEach items="${items}" var="item">
                    <tr>
                        <td id="a${item.id}">${item.id}</td>
                        <td id="b${item.id}"><e:forHtml  value="${item.name}"/></td>
                        <td id="c${item.id}">${e:forHtml(item.description)}</td>
                    </tr>
                </c:forEach>
            </tbody>
        </table>
        <%-- Items again as one JSON document: every string value is encoded
             with forJson, so the block stays inside this script element and
             JSON.parse returns the identical strings. The JSON text contains
             no raw control characters; keep it on a single line. --%>
        <script type="application/json" id="items-json">[<c:forEach items="${items}" var="item" varStatus="status">{"id":${item.id},"name":"${e:forJson(item.name)}","description":"${e:forJson(item.description)}"}<c:if test="${!status.last}">,</c:if></c:forEach>]</script>
    </body>
</html>
