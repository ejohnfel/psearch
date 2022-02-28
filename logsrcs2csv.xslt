<?xml version="1.0" encoding="iso-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text" indent="yes"/>
  <xsl:template match="/logs">
    <xsl:for-each select="log">
      <xsl:value-of select="@name"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="@group"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="@status"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="@nick"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="owner"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="source"/>
      <xsl:text>,</xsl:text>
      <xsl:for-each select="targets/target">
        <xsl:value-of select="."/>
        <xsl:if test="position()=last()-1">
          <xsl:text>|</xsl:text>
        </xsl:if>
      </xsl:for-each>
      <xsl:text>,</xsl:text>
      <xsl:for-each select="parse-info/name">
        <xsl:value-of select="."/>
        <xsl:if test="position()=last()-1">
          <xsl:text>|</xsl:text>
        </xsl:if>
      </xsl:for-each>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="description"/>
      <xsl:text>,</xsl:text>
      <xsl:value-of select="comment"/>
      <xsl:text>&#10;</xsl:text>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
