FROM rockylinux/rockylinux:10-ubi-init@sha256:9d08fffa504f757ea7e970de4409945aabc1102cb66c194f77eefa9f98e662dc AS kdc

EXPOSE 8088
EXPOSE 8464

RUN yum install -y krb5-workstation && yum update -y && yum clean all
COPY --chown=root:root krb5.conf /etc/krb5.conf
RUN chmod 644 /etc/krb5.conf

RUN yum install -y krb5-server && yum clean all
COPY --chown=root:root kdc.conf /var/kerberos/krb5kdc/kdc.conf
COPY --chown=root:root kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
RUN chmod 600 /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl

RUN systemctl enable krb5kdc.service kadmin.service

RUN kdb5_util create -s -r EXAMPLE.COM -P $(echo ${RANDOM}${RANDOM}${RANDOM} | md5sum | cut -d ' ' -f 1)

RUN kadmin.local addprinc -pw password test
RUN kadmin.local ktadd -norandkey -k /etc/test.keytab test
RUN kadmin.local addprinc -randkey host/ssh.example.com
RUN kadmin.local ktadd -k /etc/ssh.keytab host/ssh.example.com

FROM rockylinux/rockylinux:10-ubi-init@sha256:9d08fffa504f757ea7e970de4409945aabc1102cb66c194f77eefa9f98e662dc AS ssh

EXPOSE 8022

RUN yum install -y krb5-workstation && yum update -y && yum clean all
COPY --chown=root:root krb5.conf /etc/krb5.conf
RUN chmod 644 /etc/krb5.conf

RUN yum install -y openssh-server authselect && yum clean all
COPY --from=kdc --chown=root:root /etc/ssh.keytab /etc/krb5.keytab
RUN chmod 640 /etc/krb5.keytab

RUN systemctl enable sshd.service

COPY --chown=root:root sshd_config /etc/ssh/sshd_config
RUN chmod 600 /etc/ssh/sshd_config

RUN authselect select minimal --force
RUN useradd test

RUN chmod 0400 /etc/shadow

FROM scratch AS keytab
COPY --from=kdc /etc/test.keytab /test.keytab
COPY --from=kdc /etc/ssh.keytab /ssh.keytab
