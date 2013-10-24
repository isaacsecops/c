
package com.checkmarx.cxviewer.ws.generated;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SourceControlSettings complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SourceControlSettings">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Port" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="UseSSL" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="UseSSH" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="ServerName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="Repository" type="{http://Checkmarx.com/v7}RepositoryType"/>
 *         &lt;element name="UserCredentials" type="{http://Checkmarx.com/v7}Credentials" minOccurs="0"/>
 *         &lt;element name="Protocol" type="{http://Checkmarx.com/v7}SourceControlProtocolType"/>
 *         &lt;element name="RepositoryName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="ProtocolParameters" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="GITBranch" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="GitLsViewType" type="{http://Checkmarx.com/v7}GitLsRemoteViewType"/>
 *         &lt;element name="SSHPublicKey" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="SSHPrivateKey" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SourceControlSettings", propOrder = {
    "port",
    "useSSL",
    "useSSH",
    "serverName",
    "repository",
    "userCredentials",
    "protocol",
    "repositoryName",
    "protocolParameters",
    "gitBranch",
    "gitLsViewType",
    "sshPublicKey",
    "sshPrivateKey"
})
public class SourceControlSettings {

    @XmlElement(name = "Port")
    protected int port;
    @XmlElement(name = "UseSSL")
    protected boolean useSSL;
    @XmlElement(name = "UseSSH")
    protected boolean useSSH;
    @XmlElement(name = "ServerName")
    protected String serverName;
    @XmlElement(name = "Repository", required = true)
    protected RepositoryType repository;
    @XmlElement(name = "UserCredentials")
    protected Credentials userCredentials;
    @XmlElement(name = "Protocol", required = true)
    protected SourceControlProtocolType protocol;
    @XmlElement(name = "RepositoryName")
    protected String repositoryName;
    @XmlElement(name = "ProtocolParameters")
    protected String protocolParameters;
    @XmlElement(name = "GITBranch")
    protected String gitBranch;
    @XmlElement(name = "GitLsViewType", required = true)
    protected GitLsRemoteViewType gitLsViewType;
    @XmlElement(name = "SSHPublicKey")
    protected String sshPublicKey;
    @XmlElement(name = "SSHPrivateKey")
    protected String sshPrivateKey;

    /**
     * Gets the value of the port property.
     * 
     */
    public int getPort() {
        return port;
    }

    /**
     * Sets the value of the port property.
     * 
     */
    public void setPort(int value) {
        this.port = value;
    }

    /**
     * Gets the value of the useSSL property.
     * 
     */
    public boolean isUseSSL() {
        return useSSL;
    }

    /**
     * Sets the value of the useSSL property.
     * 
     */
    public void setUseSSL(boolean value) {
        this.useSSL = value;
    }

    /**
     * Gets the value of the useSSH property.
     * 
     */
    public boolean isUseSSH() {
        return useSSH;
    }

    /**
     * Sets the value of the useSSH property.
     * 
     */
    public void setUseSSH(boolean value) {
        this.useSSH = value;
    }

    /**
     * Gets the value of the serverName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getServerName() {
        return serverName;
    }

    /**
     * Sets the value of the serverName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setServerName(String value) {
        this.serverName = value;
    }

    /**
     * Gets the value of the repository property.
     * 
     * @return
     *     possible object is
     *     {@link RepositoryType }
     *     
     */
    public RepositoryType getRepository() {
        return repository;
    }

    /**
     * Sets the value of the repository property.
     * 
     * @param value
     *     allowed object is
     *     {@link RepositoryType }
     *     
     */
    public void setRepository(RepositoryType value) {
        this.repository = value;
    }

    /**
     * Gets the value of the userCredentials property.
     * 
     * @return
     *     possible object is
     *     {@link Credentials }
     *     
     */
    public Credentials getUserCredentials() {
        return userCredentials;
    }

    /**
     * Sets the value of the userCredentials property.
     * 
     * @param value
     *     allowed object is
     *     {@link Credentials }
     *     
     */
    public void setUserCredentials(Credentials value) {
        this.userCredentials = value;
    }

    /**
     * Gets the value of the protocol property.
     * 
     * @return
     *     possible object is
     *     {@link SourceControlProtocolType }
     *     
     */
    public SourceControlProtocolType getProtocol() {
        return protocol;
    }

    /**
     * Sets the value of the protocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link SourceControlProtocolType }
     *     
     */
    public void setProtocol(SourceControlProtocolType value) {
        this.protocol = value;
    }

    /**
     * Gets the value of the repositoryName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRepositoryName() {
        return repositoryName;
    }

    /**
     * Sets the value of the repositoryName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRepositoryName(String value) {
        this.repositoryName = value;
    }

    /**
     * Gets the value of the protocolParameters property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getProtocolParameters() {
        return protocolParameters;
    }

    /**
     * Sets the value of the protocolParameters property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProtocolParameters(String value) {
        this.protocolParameters = value;
    }

    /**
     * Gets the value of the gitBranch property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getGITBranch() {
        return gitBranch;
    }

    /**
     * Sets the value of the gitBranch property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setGITBranch(String value) {
        this.gitBranch = value;
    }

    /**
     * Gets the value of the gitLsViewType property.
     * 
     * @return
     *     possible object is
     *     {@link GitLsRemoteViewType }
     *     
     */
    public GitLsRemoteViewType getGitLsViewType() {
        return gitLsViewType;
    }

    /**
     * Sets the value of the gitLsViewType property.
     * 
     * @param value
     *     allowed object is
     *     {@link GitLsRemoteViewType }
     *     
     */
    public void setGitLsViewType(GitLsRemoteViewType value) {
        this.gitLsViewType = value;
    }

    /**
     * Gets the value of the sshPublicKey property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSSHPublicKey() {
        return sshPublicKey;
    }

    /**
     * Sets the value of the sshPublicKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSSHPublicKey(String value) {
        this.sshPublicKey = value;
    }

    /**
     * Gets the value of the sshPrivateKey property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSSHPrivateKey() {
        return sshPrivateKey;
    }

    /**
     * Sets the value of the sshPrivateKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSSHPrivateKey(String value) {
        this.sshPrivateKey = value;
    }

}