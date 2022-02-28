<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt" exclude-result-prefixes="msxsl">
  <xsl:output method="html" indent="yes"/>
  <xsl:template match="/logs">
    <html>
      <head>
        <link rel="stylesheet" type="text/css" href="logs.css" />
        <title>Log Sources</title>
      </head>
      <body>
        <table id="logsources">
          <tr>
            <td class="title" colspan="9">
              <h1>Logs Sources</h1>
            </td>
          </tr>
          <tr>
            <th>Log Name</th>
            <th class="col">Group</th>
            <th class="col">Nickname</th>
            <th class="col">Status</th>
            <th class="col">Description</th>
            <th class="col">Comment</th>
            <th class="col">Owner</th>
            <th class="col">Source</th>
            <th class="col">Log Names</th>
            <th class="col">Targets</th>
          </tr>
          <xsl:for-each select="log">
            <tr>
              <td>
                <xsl:value-of select="@name"/>
              </td>
              <td>
                <xsl:value-of select="@group"/>
              </td>
	      <td>
	        <xsl:value-of select="@nick"/>
	      </td>
              <td>
                <xsl:value-of select="@status"/>
              </td>
              <td>
                <xsl:value-of select="description/."/>
              </td>
              <td>
                <xsl:value-of select="comment/."/>
              </td>
              <td>
                <xsl:value-of select="owner/."/>
              </td>
              <td>
                <xsl:value-of select="source/."/>
              </td>
              <td>
                <xsl:for-each select="parse-info/name">
                  <xsl:value-of select="."/><br/>
                </xsl:for-each>
              </td>
              <td>
                <xsl:for-each select="targets/target">
                  <xsl:value-of select="."/><br/>
                </xsl:for-each>
              </td>
            </tr>
          </xsl:for-each>
        </table>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
