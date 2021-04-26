#!/bin/bash
#**************************************************
# Script: Hardening
# SO: RHEL
# Creado por: Infraestructura Linux
# Hardening acorde a PCI V3.2.1
#**************************************************

###Funciones y variables auxiliares
TEMPORAL=/tmp/tmpConf
TEMPORAL_ERROR=/tmp/tmpConf_err
SERVER=$(uname)
HOSTNAME=$(hostname)
RUTA_EVIDENCIA=/root/Hardening/$(date +%Y%m%d-%H%M)_$(hostname)
BITACORA=${RUTA_EVIDENCIA}/Bitacora
RUTA_RESPALDOS=${RUTA_EVIDENCIA}/Respaldos

mkdir -p ${RUTA_RESPALDOS}

bitacora() {
  MSG=$1
  case $2 in 
    1)
      #INFO
      SEV="///"
      ;;
    2)
      #DEBUG
      SEV=">>>"
      ;;
    3)
      #ALERT
      SEV="!!!"
      ;;
    *)
      #UNKNOWN
      SEV="???"
      ;;
  esac    
  TIME=$(date +"%Y-%m-%d %H:%M:%S")
  echo -e "$TIME ${SEV}\t${MSG}" | tee -a $BITACORA
}
export -f bitacora #Esto para poder utilizar la funcion bitacora dentro del comando xargs

respaldo() {
  FECHA=$(date +%Y%m%d-%H%M%S)
  ARCHIVO=$(echo $1 | awk -F"/" '{print $NF}')
  R_ARCHIVO=$(realpath $1)
  bitacora "Respaldando $R_ARCHIVO" 1
  cp $R_ARCHIVO ${R_ARCHIVO}_${FECHA} #Respaldo local
  cp $R_ARCHIVO ${RUTA_RESPALDOS}/${ARCHIVO}_${FECHA} #Respaldo en la fecha de ejecucion
  bitacora "Respaldado de ${R_ARCHIVO} como ${R_ARCHIVO}_${FECHA} y en ${RUTA_RESPALDOS}/${ARCHIVO}_${FECHA}" 2
}

agregarLinea() {
  DATO=$1
  ARCHIVO=$2
  bitacora "Agregando \"$DATO\" a $ARCHIVO" 1
  [[ ! -e $ARCHIVO ]] && bitacora "El archivo \"$ARCHIVO\" No existe\n" 3
  OCURRENCIA=$(grep "^${DATO}$" $ARCHIVO 2>/dev/null)
  [[ -z "$OCURRENCIA" ]] && echo "$DATO" >> $ARCHIVO && bitacora "Dato agregado" 2 || bitacora "Ya se encuentra este dato en el archivo $ARCHIVO, ignorando\n" 2
}

agregarTexto() {
  FUENTE=$1
  ARCHIVO=$2
  while read LINE
  do
    agregarLinea "$LINE" $ARCHIVO
  done < $FUENTE
}

1.1.1_eliminar_filesystems() {
  bitacora "1.1.1_eliminar_filesystems()" 1
  ##1.1 FS Configuration
  bitacora "Configuraciones de FS" 1
  #1.1.1.1 - 1.1.1.8 Deshabilitar Filesystems indeseados
  touch /etc/modprobe.d/CIS.conf 
  bitacora "Eliminando FileSystems innecesarios" 2
cat << EOF > $TEMPORAL
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
  ARCHIVO_DESTINO=/etc/modprobe.d/CIS.conf 
  agregarTexto $TEMPORAL $ARCHIVO_DESTINO

  bitacora "Removiendo filesystems con rmmod" 1
  
  bitacora "Removiendo cramfs" 2
  rmmod cramfs 
  
  bitacora "Removiendo freevxfs" 2
  rmmod freevxfs 
  
  bitacora "Removiendo jffs" 2
  rmmod jffs2 
  
  bitacora "Removiendo hfs" 2
  rmmod hfs 
  
  bitacora "Removiendo hfsplus" 2
  rmmod hfsplus 
  
  bitacora "Removiendo squashfs" 2
  rmmod squashfs 
  
  bitacora "Removiendo udf" 2
  rmmod udf 

  bitacora "En caso de no usarse, remover vfat" 2
  [[ ! $(grep vfat /etc/fstab) ]] && agregarLinea "install vfat /bin/true" /etc/modprobe.d/CIS.conf && rmmod vfat
}

1.1.1_modificar_fstab() {
  bitacora "1.1.1_modificar_fstab()" 1
  bitacora "Verificando opciones en particiones" 1
  #1.1.2 - 1.1.1.20 Modificar opciones de particiones
  respaldo /etc/fstab

  bitacora "En caso de no tenerlo, agregar opciones nodev y nosuid a /tmp" 2
  OPCIONES=$(grep -w /tmp /etc/fstab | awk '{print $4}')
  NUM_LINEA=$(grep -wn /tmp /etc/fstab | cut -d: -f1)
  [[ ! $OPCIONES == *"nodev"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},nodev/" /etc/fstab
  [[ ! $OPCIONES == *"nosuid"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},nosuid/" /etc/fstab
  #[[ ! $OPCIONES == *"noexec"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},noexec/" /etc/fstab
  
  bitacora "En caso de no tenerlo, agregar opciones nodev y nosuid a /var/tmp" 2
  OPCIONES=$(grep -w /var/tmp /etc/fstab | awk '{print $4}')
  NUM_LINEA=$(grep -wn /var/tmp /etc/fstab | cut -d: -f1)
  [[ ! $OPCIONES == *"nodev"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},nodev/" /etc/fstab
  [[ ! $OPCIONES == *"nosuid"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},nosuid/" /etc/fstab
  #[[ ! $OPCIONES == *"noexec"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},noexec/" /etc/fstab
  
  bitacora "En caso de no tenerlo, agregar opciones nodev /home" 2
  OPCIONES=$(grep -w /home /etc/fstab | awk '{print $4}')
  NUM_LINEA=$(grep -wn /home /etc/fstab | cut -d: -f1)
  [[ ! $OPCIONES == *"nodev"* ]] && sed  -i "${NUM_LINEA}s/${OPCIONES}/${OPCIONES},nodev/" /etc/fstab
  
  
  bitacora "En caso de no tenerlo, agregar opciones nodev, y nosuid en /dev/shm" 2
  #PARTICION=$(mount | grep /dev/shm | grep tmpfs | grep nodev | grep noexec | grep nosuid)
  PARTICION=$(mount | grep /dev/shm | grep tmpfs | grep nodev | grep nosuid)
  [[ -z $PARTICION ]] && agregarLinea "tmpfs  /dev/shm  tmpfs defaults,nodev,nosuid 0 0" /etc/fstab #Se quito debido a que aplicaciones como Application de BW
  
  bitacora "Remontado de /dev/shm, /tmp, /home y /var/tmp" 2
  mount -a
  mount -o remount /dev/shm
  mount -o remount /tmp
  mount -o remount /home
  mount -o remount /var/tmp
}

1.1.1_operaciones_filesystems() {
  bitacora "1.1.1_operaciones_filesystems()" 1
  bitacora "Modificando operaciones de filesystems" 1
  bitacora "Agregando Sticky bit en /tmp" 2
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs -I '{}' bash -c 'bitacora "Agregando el sticky bit a {}" 2'
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
  
  bitacora "Eliminando automounting" 2
  #1.1.1.21 Deshabilitar automounting

  bitacora "Desactivando automounting" 1
  systemctl disable autofs
}

1.2_revisar_suscripcion() {
  bitacora "1.2_revisar_suscripcion()" 1
  bitacora "Verificando status de suscripcion" 2
  #Desbloqueo de YUM para los oracle
  ps -ef | grep yum | grep -v grep  | awk '{ print "kill -9 "$2 }' | bash
  ps -ef | grep rpm | grep -v grep  | awk '{ print "kill -9 "$2 }' | bash
  rm -f /var/lib/rpm/__db*
  rm -f /var/lib/rpm/.rpm.lock
  rm -f /var/lib/rpm/.dbenv.lock

  #1.2.1 Verificando configuracion de repositorios del manejador de paquetes
  bitacora "Verificando configuracion de repositorios del manejador de paquetes" 2
  yum repolist all
  
  #1.2.2 GpgCheck activado globalmente
  bitacora "GpgCheck activado globalmente" 2
  bitacora "GpgCheck activado globalmente" 2
  cp /etc/yum.conf /etc/yum.conf.bkp_$(date +"%Y%m%d")
  agregarLinea "gpgcheck=1" /etc/yum.conf
  
  #1.2.4 Verificacion de suscripcion del equipo
  bitacora "Verificacion de suscripcion del equipo" 2
  [[ $(subscription-manager status | grep -i current) ]] && bitacora "Equipo suscrito" 2 || bitacora "El equipo no se encuentra suscrito" 2
  
  #1.2.5 Deshabilitacion de rhnsd
  bitacora "Deshabilitacion de rhnsd" 2
  chkconfig rhnsd off
}

1.3_checar_integridad_fs() {
  bitacora "1.3_checar_integridad_fs()" 1
  ##1.3 Chequeo de integridad en FileSystems
  #1.3.1 - 1.3.2 Configuracion de AIDE
  bitacora "Chequeo de integridad en FileSystems" 1
  
  if [[ ! $(rpm -qa | egrep "aide-[0-9]+" ) ]]; then
    bitacora "Instalando y configurando AIDE" 2
    yum install -y aide
    aide --init
  else
    bitacora "AIDE ya se encuentra instalado" 2
  fi
  
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  
  actualCron=$(crontab -l | grep "/usr/bin/aide --check")
  bitacora "Estableciendo chequeos periodicos de AIDE" 2
  if [ -z "$actualCron" ]; then
    crontab -l > /tmp/tmpcron
    agregarLinea "30 2 * * 0 /usr/sbin/aide --check" /tmp/tmpcron
    crontab /tmp/tmpcron
    agregarLinea "30 2 * * 0 /usr/sbin/aide --check" /etc/crontab
    rm /tmp/tmpcron
  fi
}

1.4_configuraciones_seguras_boot() {
  bitacora "1.4_configuraciones_seguras_boot()" 1
  ##1.4 Configuraciones seguras de Boot
  bitacora "Configuraciones seguras de Boot" 1
  #1.4.1 Configuracion de permisos de bootloader
  bitacora "Cambiando dueño de /boot/grub2/grub.cfg a root:root" 2
  chown root:root /boot/grub2/grub.cfg
  bitacora "Cambiando permisos de /boot/grub2/grub.cfg a 640" 2
  chmod 640 /boot/grub2/grub.cfg

  #1.4.2 Son configuradas por el area de seguridad
  #1.4.3 Asegurar que sea requerida autenticacion en modo single user
  bitacora "Asegurar que sea requerida autenticacion en modo single user" 1
  respaldo /usr/lib/systemd/system/rescue.service
  respaldo /usr/lib/systemd/system/emergency.service
  for FILE in $(ls /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service); do
    [[ -n $(grep ExecStart $FILE | grep -v "#") ]] && sed -i 's/ExecStart.*/ExecStart=-\/bin\/sh -c "\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/' $FILE || agregarLinea "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" $FILE
  done
}

1.5_procesos_adicionales_hardening() {
  bitacora "1.5_procesos_adicionales_hardening()" 1
  ##1.5 Procesos adicionales de Hardening
  bitacora "Procesos adicionales de Hardening" 1

  #1.5.1 Restriccion de core dumps
  bitacora "Restriccion de core dumps" 2
  respaldo /etc/security/limits.conf
  agregarLinea "* hard core 0" /etc/security/limits.conf
  sysctl -w fs.suid_dumpable=0
  #1.5.2 no lo aplicamos desde el script debido a que se configura desde la bios 
  #1.5.3 Habilitacion de ASLR
  respaldo /etc/sysctl.conf
  bitacora "Habilitacion de ASLR" 2
  agregarLinea "kernel.randomize_va_space = 2" /etc/sysctl.conf
  sysctl -w kernel.randomize_va_space=2
  
  #1.5.4 Deshabilitacion de prelink
  bitacora "Deshabilitacion de prelink" 2
  if [[ $(rpm -qa | grep prelink ) ]]; then
    bitacora "Deshabilitando prelink" 2
    prelink -ua
    yum remove -y prelink
  else
    bitacora "prelink no esta instalado" 2
  fi
}

1.6_configuraciones_mac_selinux() {
  bitacora "1.6_configuraciones_mac_selinux()" 1
  ##1.6 Mandatory Access Control
  bitacora "Mandatory Access Control" 1
  #1.6.2 SELinux Instalado
  [[ ! $(rpm -qa | grep libselinux) ]] && yum install -y libselinux
  bitacora "SELinux Instalado" 2

  #1.6.1.1 SELinux no desabilitado en la configuracion de bootloader
  bitacora "SELinux no desabilitado en la configuracion de bootloader" 2
  
  RUTA_GRUB=/boot/grub2/grub.cfg #RHEL7
  [[ ! -e $RUTA_GRUB ]] && RUTA_GRUB=/boot/grub/grub.cfg #RHEL6
  respaldo $RUTA_GRUB
  
  bitacora "Habilitando selinux desde GRUB" 2
  if [[ $(egrep "selinux=0|enforcing=0" /etc/default/grub) ]]; then
    sed -i '/GRUB_CMDLINE_LINUX_DEFAULT=/s/selinux=0/selinux=1/' /etc/default/grub
    sed -i '/GRUB_CMDLINE_LINUX=/s/selinux=0/selinux=1/' /etc/default/grub
    grub2-mkconfig > $RUTA_GRUB
    bitacora "SELinux rehabilitado dentro de GRUB" 2
  else
    bitacora "SELinux no estaba deshabilitado en GRUB" 2
  fi
  
  #1.6.1.2 SELinux en modo enforcing 
  bitacora "SELinux debe estar en modo enforcing " 2
  respaldo /etc/selinux/config 
  
  if [[ $(grep "SELINUX=enforcing" /etc/selinux/config) ]]; then
    bitacora "SELinux esta en modo enforcing dentro del archivo /etc/selinux/config" 2
  else
    bitacora "Estableciendo el modo enforcing dentro del archivo /etc/selinux/config" 2
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config
    sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config
  fi
  
  #1.6.1.3 Politica de SELinux
  bitacora "Politica de SELinux" 1
  if [[ ! $(grep -e "SELINUXTYPE=targeted" -e "SELINUXTYPE=mls" /etc/selinux/config) ]]; then
    sed -i 's/^SELINUXTYPE=.*$/^SELINUXTYPE=targeted$/g' /etc/selinux/config 
    bitacora "Politica de SELinux establecida" 2
  else
    bitacora "La politica de SELinux ya estaba establecida" 2
  fi
  
  
  #1.6.1.4 SETroubleshoot desinstalado
  bitacora "SETroubleshoot desinstalado" 1
  if [[ $(rpm -qa | grep setroubleshoot ) ]]; then
    yum remove -y setroubleshoot
    bitacora "Se ha desinstalado setroubleshoot" 2
  else
    bitacora "setroubleshoot ya estaba desinstalado en el servidor" 2
  fi
}
  
1.6_configuraciones_mac_extras() {
  bitacora "1.6_configuraciones_mac_extras()" 1
  #1.6.1.5 MCS Translation Service (mctrans) no debe estar instalado
  bitacora "MCS Translation Service (mctrans) no debe estar instalado" 1
  if [[ $(rpm -qa | grep mctrans) ]]; then
    yum remove -y mctrans
    bitacora "Se ha desinstalado mctrans" 2
  else
    bitacora "mctrans esta desinstalado en el servidor" 2
  fi
  
  #1.6.1.6 No existencia de daemons sin confinamiento
  bitacora "No existencia de daemons sin confinamiento" 1
  UNCONFINED=$(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }')
  if [[ -n $UNCONFINED ]]; then
    bitacora "daemons sin confinamiento que requieren atencion" 2
    echo $UNCONFINED
  else
    bitacora "No existen daemons sin confinamiento" 2
  fi
}

1.7_banners() {
  bitacora "1.7_banners()" 1
  ##1.7 Banners de advertencia
  bitacora "Configuracion de banners de advertencia" 1
  #1.7.1.1 - 1.7.1.6 Configuracion de banners de seguridad
  
  bitacora "Configuracion de permisos, pertenencia y contenido de /etc/motd" 2
  chmod 644 /etc/motd
  chown root:root /etc/motd      
  echo "Todo acceso al equipo puede ser monitoreado por la Oficina de Seguridad de la Información" > /etc/motd
  
  bitacora "Configuracion de permisos, pertenencia y contenido de /etc/issue" 2
  chmod 644 /etc/issue
  chown root:root /etc/issue
  echo "Todo acceso al equipo puede ser monitoreado por la Oficina de Seguridad de la Información" > /etc/issue
  
  bitacora "Configuracion de permisos, pertenencia y contenido de /etc/issue.net" 2
  chmod 644 /etc/issue.net
  chown root:root /etc/issue.net
  echo "Todo acceso al equipo puede ser monitoreado por la Oficina de Seguridad de la Información" > /etc/issue.net
}

1.8_actualizaciones_seguridad() {
  bitacora "1.8_actualizaciones_seguridad()" 1
  #1.8 Actualizaciones de seguridad 
  bitacora "Actualizaciones de seguridad " 1
  yum update -y --security
}

2.1_servicios_inetd() {
  bitacora "2.1_servicios_inetd()" 1
  ##2.1 Servicios Inetd
  bitacora "Deshabilitando servicios Inetd inusuales" 1
  bitacora "Deshabilitando chargen-dgram" 2
  chkconfig chargen-dgram off >/dev/null 2>/dev/null
  bitacora "Deshabilitando chargen-stream" 2
  chkconfig chargen-stream off >/dev/null 2>/dev/null
  bitacora "Deshabilitando daytime-dgram" 2
  chkconfig daytime-dgram off >/dev/null 2>/dev/null
  bitacora "Deshabilitando daytime-stream" 2
  chkconfig daytime-stream off >/dev/null 2>/dev/null
  bitacora "Deshabilitando discard-dgram" 2
  chkconfig discard-dgram off >/dev/null 2>/dev/null
  bitacora "Deshabilitando discard-stream" 2
  chkconfig discard-stream off >/dev/null 2>/dev/null
  bitacora "Deshabilitando echo-dgram" 2
  chkconfig echo-dgram off >/dev/null 2>/dev/null
  bitacora "Deshabilitando echo-stream" 2
  chkconfig echo-stream off >/dev/null 2>/dev/null
  bitacora "Deshabilitando time-dgram" 2
  chkconfig time-dgram off >/dev/null 2>/dev/null
  bitacora "Deshabilitando time-stream" 2
  chkconfig time-stream off >/dev/null 2>/dev/null
  bitacora "Deshabilitando tftp" 2
  chkconfig tftp off >/dev/null 2>/dev/null
  bitacora "Deshabilitando xinetd" 2
  systemctl disable xinetd >/dev/null 2>/dev/null
}

2.2_servicios_proposito_especial() {
  bitacora "2.2_servicios_proposito_especial()" 1
  ##2.2 Servicios de proposito especial
  bitacora "Servicios de proposito especial" 1
  bitacora "Configuracion de NTP" 1
  bitacora "Verificandos servicio de sincronizacion de tiempo" 2
  [[ ! $(rpm -qa | grep chrony) ]] && yum install -y chrony
  systemctl enable --now chronyd
  
  RUTA=/etc/chrony.conf
  [[ ! -e $RUTA ]] && RUTA=/etc/ntp.conf
  respaldo $RUTA 

  SEGMENTO=$(ip addr show ens192 2>/dev/null|awk '/inet/ {print $2}' | cut -d/ -f1)
  MTY=(172.17.201 172.17.202 172.17.203 172.17.206 172.17.207 172.17.208 172.17.211 172.17.212 172.17.218 172.17.219 172.21.201 172.21.202 172.21.203 172.22.192 172.27.203 201.116.168)
  STF=(10.16.96 172.21.253 172.22.188 172.22.201 172.22.209 172.22.220)
  QRO=(172.16.201 172.16.202 172.16.203 172.16.204 172.16.212 172.16.213 172.16.215 172.16.216 172.21.208 172.21.209 172.21.210) 
  if [[ -n $SEGMENTO ]]; then 
    [[ ${QRO[*]} =~ $SEGMENTO ]] && SITE=QRO
    [[ ${STF[*]} =~ $SEGMENTO ]] && SITE=STF
    [[ ${MTY[*]} =~ $SEGMENTO ]] && SITE=MTY
  fi
  if [[ $SITE == "MTY" ]]; then
    agregarLinea "server 172.17.210.9  iburst prefer" $RUTA
    agregarLinea "server 172.22.200.26 iburst" $RUTA
    agregarLinea "server 172.16.200.9  iburst" $RUTA
  elif [[ $SITE == "QRO" ]]; then
    agregarLinea "server 172.16.200.9  iburst prefer" $RUTA
    agregarLinea "server 172.17.210.9  iburst" $RUTA
    agregarLinea "server 172.22.200.26 iburst" $RUTA
  elif [[ $SITE == "STF" ]]; then
    agregarLinea "server 172.22.200.26 iburst prefer" $RUTA
    agregarLinea "server 172.17.210.9  iburst" $RUTA
    agregarLinea "server 172.16.200.9  iburst" $RUTA
  else
    bitacora "No se pudo obtener correctamente la ip" 3
  fi
  
  respaldo /etc/sysconfig/chronyd 
  
  [[ ! $(grep -e "^OPTIONS=\".*-u chrony.*\"" /etc/sysconfig/chronyd) ]] && sed -i '/^OPTIONS=/s/="/="-u chrony /' /etc/sysconfig/chronyd && bitacora "Agregada la opcion '-u chrony' a /etc/sysconfig/chronyd" 2 
  
  bitacora "Validar que xorg no este instalado" 2
  if [[ $(rpm -qa | grep xorg-x11) ]]; then
       yum remove -y xorg-x11*
       bitacora "Se ha desinstalado xorg-x11" 2
  else
       bitacora "xorg-x11 no esta instalado en el servidor" 2
  fi
  
  bitacora "Avahi debe estar desinstalado" 1
  if [[ $(rpm -qa | grep avahi-daemon ) ]]; then
       yum remove -y avahi-dnsconfd
       bitacora "Se ha desinstalado avahi-daemon" 2
  else
       bitacora "avahi-daemon esta desinstalado en el servidor" 2
  fi
  
  bitacora "Cups debe estar desinstalado" 1
  if [[ $(rpm -qa | grep cups ) ]]; then
       yum remove -y cups
       bitacora "Se ha desinstalado cups" 2
  else
       bitacora "cups esta desinstalado en el servidor" 2
  fi
  
  bitacora "Dhcpd debe estar desinstalado" 1
  if [[ $(rpm -qa | grep dhcp  ) ]]; then
       yum remove -y dhcp dhcp-libs
       bitacora "Se ha desinstalado dhcpd" 2
  else
       bitacora "dhcpd esta desinstalado en el servidor" 2
  fi
  
  bitacora "Ldap debe estar desinstalado" 1
  if [[ $(rpm -qa | grep openldap-servers) ]]; then
       yum remove -y openldap-servers
       bitacora "Se ha desinstalado slapd" 2
  else
       bitacora "slapd esta desinstalado en el servidor" 2
  fi
  
  bitacora "Verificando uso de NFS/RPCBIPND" 1
  if [[ ! $(grep ":/" /etc/fstab | grep -v "#") ]] && [[ ! -s /etc/exports ]]; then
    systemctl stop nfs
    systemctl stop rpcbind
    yum remove -y rpcbind nfs-utils
    bitacora "Eliminacion de software de nfs sin utilizar" 2
  else
    yum install -y rpcbind nfs-utils
    systemctl enable --now nfs
    systemctl enable --now rpcbind
    bitacora "Instalando y configurando software nfs necesario" 2
  fi
  
  bitacora "BIND NAMED deshabilitado" 1
  if [[ $(rpm -qa | grep bind ) ]]; then
    yum remove -y bind
    bitacora "Se ha desinstalado bind" 2
  else
    bitacora "bind esta desinstalado en el servidor" 2
  fi
  
  bitacora "FTP deshabilitado" 1
  if [[ $(rpm -qa | grep ftp ) ]]; then
    yum remove -y ftp
    bitacora "Se ha desinstalado ftp" 2
  else
    bitacora "ftp esta desinstalado en el servidor" 2
  fi
  
  #echo -e "---\t HTTP deshabilitado"
  #if [[ $(rpm -qa | grep httpd) ]]; then
	  #systemctl disable httpd
    #yum remove -y httpd
    #echo -e ">>>\t Se ha desinstalado httpd"
  #else
    #echo -e ">>>\t httpd esta desinstalado en el servidor"
  #fi
  
  ##2.2.8
  bitacora "Deshabilitando servicio named" 2
  systemctl disable named
  
  ##2.2.14
  bitacora "Deshabilitando servicio snmpd" 2
  systemctl disable snmpd
  
  ##2.2.15
  bitacora "Configurando servicio postfix" 2
  sed -i '/inet_interfaces/d' /etc/postfix/main.cf
  agregarLinea "inet_interfaces = loopback-only" /etc/postfix/main.cf
  systemctl restart postfix
  
  bitacora "Dovecot deshabilitado" 1
  if [[ $(rpm -qa | grep dovecot ) ]]; then
    yum remove -y dovecot
    bitacora "Se ha desinstalado dovecot" 2
  else
    bitacora "dovecot esta desinstalado en el servidor" 2
  fi
  
  bitacora "SAMBA deshabilitado" 1
  if [[ $(rpm -qa | grep samba ) ]]; then
    yum remove -y samba
    bitacora "Se ha desinstalado samba" 2
  else
    bitacora "samba esta desinstalado en el servidor" 2
  fi
  
  bitacora "SQUID Deshabilitado" 1
  if [[ $(rpm -qa | grep squid ) ]]; then
    yum remove -y squid
    bitacora "Se ha desinstalado squid" 2
  else
    bitacora "squid esta desinstalado en el servidor" 2
  fi
  
  bitacora "TFTP Deshabilitado" 2
  systemctl disable tftp.socket
  
  bitacora "RSYNC Deshabilitado" 2
  systemctl disable rsyncd
  
  ##2.3 Servicions Clientes
  bitacora "NIS Desinstalado" 1
  if [[ $(rpm -qa | grep ypserv ) ]]; then
    yum remove -y ypserv
    bitacora "Se ha desinstalado ypserv" 2
  else
    bitacora "ypserv esta desinstalado en el servidor" 2
  fi
  
  bitacora "YPBIND desinstalado" 1
  if [[ $(rpm -qa | grep ypbind ) ]]; then
       yum remove -y ypbind
       bitacora "Se ha desinstalado ypbind" 2
  else
       bitacora "ypbind esta desinstalado en el servidor" 2
  fi
  
  bitacora "RSH Desinstalado" 1
  if [[ $(rpm -qa | grep rsh-server ) ]]; then
    yum remove -y rsh
    bitacora "Se ha desinstalado rhs-server" 2
  else
    bitacora "rhs-server esta desinstalado en el servidor" 2
  fi
  
  bitacora "TALK desinstalado" 1
  if [[ $(rpm -qa | grep talk ) ]]; then
    yum remove -y talk
    bitacora "Se ha desinstalado talk" 2
  else
    bitacora "talk esta desinstalado en el servidor" 2
  fi
  
  bitacora "TELNET desinstalado" 1
  systemctl disable telnet.socket
  if [[ $(rpm -qa | grep telnet ) ]]; then
    yum remove -y telnet
    bitacora "Se ha desinstalado telnet" 2
  else
    bitacora "telnet esta desinstalado en el servidor" 2
  fi
  
  bitacora "OPENLDAP CLIENTE desinstalado" 1
  if [[ $(rpm -qa | grep openldap-clients ) ]]; then
    yum remove -y openldap-clients
    bitacora "Se ha desinstalado el cliente de openldap" 2
  else
    bitacora "el cliente de openldap esta desinstalado en el servidor" 2
fi
}

3.1_parametros_red() {
  bitacora "3.1_parametros_red()" 1
  ##3.1 Parametros de red
  bitacora "Parametros de Red" 1
  
  bitacora "IP Forwarding" 2
  agregarLinea "net.ipv4.ip_forward = 0" /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=0
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "Redireccionamiento de paquetes" 2
  agregarLinea "net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.all.accept_source_route = 0" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv4.conf.default.send_redirects=0
  sysctl -w net.ipv4.conf.all.accept_source_route=0
  sysctl -w net.ipv4.conf.default.accept_source_route=0
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "Source Routing" 2
  agregarLinea "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.default.accept_redirects=0
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "ICMP REDIRECTS" 2
  agregarLinea "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.default.accept_redirects=0
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "ICMP SEGURO" 2
  agregarLinea "net.ipv4.conf.all.secure_redirects = 0" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.secure_redirects = 0" /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.secure_redirects=0
  sysctl -w net.ipv4.conf.default.secure_redirects=0
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "Tratamiento de paquetes sospechosos" 2
  agregarLinea "net.ipv4.conf.all.log_martians = 1" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.log_martians = 1" /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.log_martians=1
  sysctl -w net.ipv4.conf.default.log_martians=1
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "ICMP Broadcast" 2
  agregarLinea "net.ipv4.icmp_echo_ignore_broadcasts = 1" /etc/sysctl.conf
  sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "ICMP Respuestas falsas" 2
  agregarLinea "net.ipv4.icmp_ignore_bogus_error_responses = 1" /etc/sysctl.conf
  sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "Reverse Path Filtering" 2
  agregarLinea "net.ipv4.conf.all.rp_filter = 1" /etc/sysctl.conf
  agregarLinea "net.ipv4.conf.default.rp_filter = 1" /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.rp_filter=1
  sysctl -w net.ipv4.conf.default.rp_filter=1
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "TCP SYN Cookies" 2
  agregarLinea "net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf
  sysctl -w net.ipv4.tcp_syncookies=1
  sysctl -w net.ipv4.route.flush=1
  
  bitacora "TCP-WRAPPERS instalado" 1
  if [[ $(rpm -qa | grep tcp_wrappers ) ]]; then
       bitacora "tcp-wrappers esta instalado" 2
  else
       yum -y install tcp_wrappers tcp_wrappers-libs	
       bitacora "tcp-wrappers ha sido instalado en el servidor" 2
  fi
}

3.1_parametros_red_ipv6() {
  bitacora "3.1_parametros_red_ipv6()" 1
  bitacora "Configuracion de IPv6" 2
  agregarLinea "net.ipv6.conf.all.accept_ra = 0" /etc/sysctl.conf
  agregarLinea "net.ipv6.conf.default.accept_ra = 0" /etc/sysctl.conf
  agregarLinea "net.ipv6.conf.all.accept_redirects = 0" /etc/sysctl.conf
  agregarLinea "net.ipv6.conf.default.accept_redirects = 0" /etc/sysctl.conf
  sysctl -w net.ipv6.conf.all.accept_redirects=0 
  sysctl -w net.ipv6.conf.default.accept_redirects=0
  sysctl -w net.ipv6.conf.all.accept_ra=0 
  sysctl -w net.ipv6.conf.default.accept_ra=0 
  sysctl -w net.ipv6.route.flush=1
  bitacora "ipv6 Deshabilitado" 2
  
  #if [[ $RUTA_GRUB = "/boot/grub/grub.cfg" ]]; then
  #  sed -i '/GRUB_CMDLINE_LINUX=/s/="/="ipv6.disable=1 /' $RUTA_GRUB #RHEL6
  #else
  #  sed -i '/GRUB_CMDLINE_LINUX=/s/="/="ipv6.disable=1 /' /etc/default/grub #RHEL7
  #  grub2-mkconfig -o $RUTA_GRUB
  #fi
  #bitacora "ipv6 ha sido deshabilitado, pero es necesario reiniciar para tomar este parametro en algunos programas, como rpcbind" 3
}

3.4_configuracion_red() {
  bitacora "3.4_configuracion_red()" 1
  #3.4.2, 3.4.3 Nota: /etc/hosts.allow y /etc/hosts.deny deben configurarse manualmente
  
  bitacora "Configuracion de los permisos de /etc/hosts.*" 1
  bitacora "Cambio de permisos de /etc/hosts.* a 644" 2
  chmod 644 /etc/hosts.*
  bitacora "Cambio de pertenencia de /etc/hosts.allow y /etc/hosts.deny a root" 2
  chown root:root /etc/hosts.allow
  chown root:root /etc/hosts.deny
  
  ##3.5 Deshabilitacion protocolos de red no comunes
  bitacora "Deshabilitacion de protocolos de red no comunes" 1
  bitacora "Restringiendo udf en modprobe" 2
  agregarLinea "install udf /bin/true" /etc/modprobe.d/CIS.conf
  bitacora "Restringiendo dccp en modprobe" 2
  agregarLinea "install dccp /bin/true" /etc/modprobe.d/CIS.conf
  bitacora "Restringiendo sctp en modprobe" 2
  agregarLinea "install sctp /bin/true" /etc/modprobe.d/CIS.conf
  bitacora "Restringiendo rds en modprobe" 2
  agregarLinea "install rds /bin/true" /etc/modprobe.d/CIS.conf
  bitacora "Restringiendo tipc en modprobe" 2
  agregarLinea "install tipc /bin/true" /etc/modprobe.d/CIS.conf
}

3.6_configuracion_auditd() {
  bitacora "3.6_configuracion_audit()"  2
#3.6 Nota: Configuraciones de Firewall aplican? No viene dentro del CIS de Liverpool

  ##4.1 Configuracion de auditorias del sistema (auditd)
  bitacora "Configuracion de auditorias del sistema (auditd)" 1

  bitacora "Instalando auditd." 1
  yum install -y audit

  bitacora "Configuracion de retencion de datos" 2
  bitacora "Eliminando otras coincidencias de opcion max_log_file_action" 2
  sed -i '/max_log_file_action =/d' /etc/audit/auditd.conf
  agregarLinea "max_log_file_action = rotate" /etc/audit/auditd.conf
  
  bitacora "Eliminando otras coincidencias de opcion max_log_file" 2
  sed -i '/max_log_file =/d' /etc/audit/auditd.conf
  agregarLinea "max_log_file = 32" /etc/audit/auditd.conf
  
  bitacora "Eliminando otras coincidencias de opcion space_left_action" 2
  sed -i '/space_left_action =/d' /etc/audit/auditd.conf
  agregarLinea "space_left_action = email" /etc/audit/auditd.conf
  
  bitacora "Eliminando otras coincidencias de opcion action_mail_act" 2
  sed -i '/action_mail_acct =/d' /etc/audit/auditd.conf
  agregarLinea "action_mail_acct = root" /etc/audit/auditd.conf
  
  bitacora "Eliminando otras coincidencias de opcion admin_space_left_action" 2
  sed -i '/admin_space_left_action =/d' /etc/audit/auditd.conf
  agregarLinea "admin_space_left_action = suspend" /etc/audit/auditd.conf
  
  bitacora "Habilitar servicio auditd." 2
  systemctl enable --now auditd
  
  bitacora "Asegurarse que los procesos que inician antes de auditd se encuentran registrados en logs." 2
  RUTA_GRUB=/boot/grub2/grub.cfg #RHEL7
  [[ ! -e $RUTA_GRUB ]] && RUTA_GRUB=/boot/grub/grub.cfg #RHEL6
  respaldo $RUTA_GRUB
  if [[ ! $(egrep "audit=1" /etc/default/grub) ]]; then
    sed -i '/GRUB_CMDLINE_LINUX=/s/="/="audit=1 /' /etc/default/grub
    grub2-mkconfig > $RUTA_GRUB
    bitacora "Audit rehabilitado" 2
  else
    bitacora "Audit no estaba deshabilitado" 2
  fi
}

3.6_reglas_audit() {
  bitacora "Agregar reglas generales de audit.rules." 1
  
  AUID_VAL=1000
  [[ -n $(grep "6\." /etc/*release) ]] && AUID_VAL=500

cat << EOF > $TEMPORAL
-D 
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k logins 
-w /var/log/btmp -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF
  ARCHIVO_DESTINO=/etc/audit/rules.d/audit.rules
  agregarTexto $TEMPORAL $ARCHIVO_DESTINO


  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' > $TEMPORAL
  agregarTexto $TEMPORAL $ARCHIVO_DESTINO
  
  find /opt/ -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' > $TEMPORAL
  agregarTexto $TEMPORAL $ARCHIVO_DESTINO
  
  bitacora "Recarga de reglas de audit" 2
  
  sed -i "s/auid>=1000/auid>=${AUID_VAL}/" /etc/audit/rules.d/audit.rules
  
  auditctl -R /etc/audit/rules.d/audit.rules
  auditctl -R /etc/audit/audit.rules
  auditctl -l
  service auditd reload
}

4.2_configuracion_logs() {
  bitacora "4.2_configuracion_logs()" 1
  ##4.2 Configuracion de logs
  #4.2.1.1, 4.2.3
  
  bitacora "Configuracion de logs" 1
  bitacora "Instalacion y habilitacion de rsyslog" 2
  yum install -y rsyslog
  systemctl enable --now rsyslog
  
  bitacora "Configuracion de rsyslog" 2
  #4.2.1.2, 4.2.1.3, 4.2.1.4, 4.2.1.5
cat << EOF > $TEMPORAL
*.emerg :omusrmsg:*
mail.* -/var/log/mail
mail.info -/var/log/mail.info
mail.warning -/var/log/mail.warn
mail.err /var/log/mail.err
news.crit -/var/log/news/news.crit
news.err -/var/log/news/news.err
news.notice -/var/log/news/news.notice
*.=warning;*.=err -/var/log/warn
*.crit /var/log/warn
*.*;mail.none;news.none -/var/log/messages
local0,local1.* -/var/log/localmessages
local2,local3.* -/var/log/localmessages
local4,local5.* -/var/log/localmessages
local6,local7.* -/var/log/localmessages
\$FileCreateMode 0640
# *.* @@localhost
# \$ModLoad imtcp
# \$InputTCPServerRun 514
EOF
  ARCHIVO_DESTINO=/etc/rsyslog.conf
  respaldo $ARCHIVO_DESTINO 
  agregarTexto $TEMPORAL $ARCHIVO_DESTINO
  bitacora "Definir permisos de lectura y escritura" 2
  chmod 640 /etc/rsyslog.conf
  bitacora "Reinicio de rsyslog" 2
  pkill -HUP rsyslogd
}

5.1_configuracion_cron() {
  bitacora "5.1_configuracion_cron()" 1
  ##5.1 Configuracion de cron
  bitacora "Configuracion de cron" 1
  bitacora "Habilitacion de cron" 2
  systemctl enable crond
  
  bitacora "Configuracion de permisos de cron" 2

  [[ ! -f /etc/cron.allow ]] && touch /etc/cron.allow && bitacora "Se creo el archivo /etc/cron.allow" 2
  [[ ! -f /etc/cron.deny ]] && touch /etc/cron.deny && bitacora "Se creo el archivo /etc/cron.deny" 2
  [[ ! -f /etc/at.allow ]] && touch /etc/at.allow && bitacora "Se creo el archivo /etc/at.allow" 2
  [[ ! -f /etc/at.deny ]] && touch /etc/at.deny && bitacora "Se creo el archivo /etc/at.deny" 2
  chown root:root /etc/cron*
  chmod 600 /etc/cron.*
  chmod 600 /etc/crontab
}

###5.2 Configuracion de SSH
#echo -e ">>>\t Configuracion de permisos de ssh"
#chown root:root /etc/ssh/sshd_config 
#chmod og-rwx /etc/ssh/sshd_config
#
#echo -e ">>>\t Respaldo de sshd_config"
#cp /etc/ssh/sshd_config /etc/ssh/sshd_config_bkp
#
#echo -e ">>>\t Configurar version 2 del protocolo"
#sed -i '/Protocol/d' /etc/ssh/sshd_config
#agregarLinea "Protocol 2" /etc/ssh/sshd_config
#
#echo -e ">>>\t Configurar LogLevel en INFO"
#sed -i '/LogLevel/d' /etc/ssh/sshd_config
#agregarLinea "LogLevel INFO" /etc/ssh/sshd_config
#
#echo -e ">>>\t Desactivar el reenvio X11"
#sed -i '/X11Forwarding/d' /etc/ssh/sshd_config
#agregarLinea "X11Forwarding no" /etc/ssh/sshd_config
#
#echo -e ">>>\t Configurar MaxAuthTries en 3 o menor."
#sed -i '/MaxAuthTries/d' /etc/ssh/sshd_config
#agregarLinea "MaxAuthTries 3" /etc/ssh/sshd_config
#
#echo -e ">>>\t Habilitar IgnoreRhosts"
#sed -i '/IgnoreRhosts/d' /etc/ssh/sshd_config
#agregarLinea "IgnoreRhosts yes" /etc/ssh/sshd_config
#
#echo -e ">>>\t Desactivar HostbasedAuthentication"
#sed -i '/HostbasedAuthentication /d' /etc/ssh/sshd_config
#agregarLinea "HostbasedAuthentication no" /etc/ssh/sshd_config
#
##5.2.8 Nota: Ensure SSH root login is disabled no puede aplicarse debido al uso de satellite
#
#echo -e ">>>\t Desactivar PermitEmptyPasswords."
#sed -i '/PermitEmptyPasswords/d' /etc/ssh/sshd_config
#agregarLinea "PermitEmptyPasswords no" /etc/ssh/sshd_config
#
#echo -e ">>>\t Desactivar PermitUserEnvironment."
#sed -i '/PermitUserEnvironment/d' /etc/ssh/sshd_config
#agregarLinea "PermitUserEnvironment no" /etc/ssh/sshd_config
#
##5.2.11 - 5.2.15 Nota: Estos puntos son configurados por el Area de seguridad
#
#echo -e ">>>\t Recarga de ssh"
#systemctl reload sshd

##5.3 Configuracion de PAM. Nota: Estos puntos son configurados por el Area de seguridad

5.4._cuentas_y_ambiente() {
  bitacora "5.4._cuentas_y_ambiente()" 1
  ##5.4 User Accounts and Environment
  #5.4.1 Set Shadow Password Suite Parameters. Nota: Estos puntos son configurados por el Area de seguridad
  #5.4.2 Las cuentas de sistema deben ser de tipo no-login
  bitacora "Las cuentas de sistema deben ser de tipo no-login" 1
  ID_USUARIOS=1000
  [[ -n $(grep "6\." /etc/*release) ]] && ID_USUARIOS=500
  for user in $(awk -v ID_U=$ID_USUARIOS -F: '($3 < ID_U) {print $1}' /etc/passwd) ; do
    if [[ $user != root ]]; then  
      usermod -L $user
      [[ $user != sync ]] && [[ $user != shutdown ]] && [[ $user != halt ]] && bitacora "cambiando shell de $user a no-login" 2
      [[ $user != sync ]] && [[ $user != shutdown ]] && [[ $user != halt ]] && usermod -s /sbin/nologin $user
    fi
  done

  #5.4.3 El grupo default del usuario Root debe ser 0
  bitacora "El grupo default del usuario Root debe ser 0" 2
  ROOT_GID=$(grep "^root:" /etc/passwd | cut -f4 -d:)
  [[ $ROOT_GID != 0 ]] && bitacora "Corrigiendo grupo del usuario root" 2 || bitacora "Root ya tiene su grupo correcto" 2
  [[ $ROOT_GID != 0 ]] && usermod -g 0 root

  #5.4.4 Umask por default debe ser 027
  #echo -e ">>>\t Umask por default debe ser 027"
  #for FILE in $(ls /etc/*shrc /etc/profile /etc/profile.d/*.sh); do
  #  agregarLinea "umask 027" $FILE
  #done
  
  #5.4.5 - 5.6 Nota: verificar si estas reglas deben configurarse por el area de infraestructura o por el area de seguridad

}

6.1_permisos_archivos_sistema() {
  bitacora "6.1_permisos_archivos_sistema()" 1
  #6.1 Permisos de archivos del sistema
  bitacora "Permisos de archivos del sistema" 1

  #6.1.1 Auditoria de permisos de archivos del sistema
  bitacora "Auditoria de permisos de archivos del sistema" 1
  bitacora "Los siguientes son los resultados de la revision de archivos de paquetes:" 2
  rpm -Va --nomtime --nosize --nomd5 --nolinkto >> $BITACORA

  #6.1.2 - 6.1.9 Auditoria de permisos de archivos del sistema
  bitacora "Modificando pertenencia y permisos a archivos passwd, shadow, group, gshadow, passwd-, shadow-, group- y gshadow-" 2
  chown root:root /etc/passwd
  chmod 644 /etc/passwd  
  chown root:root /etc/shadow
  chmod 000 /etc/shadow
  chown root:root /etc/group
  chmod 644 /etc/group    
  chown root:root /etc/gshadow
  chmod 000 /etc/gshadow
  chown root:root /etc/passwd-
  chmod 400 /etc/passwd-
  chown root:root /etc/shadow-
  chmod 000 /etc/shadow-
  chown root:root /etc/group-
  chmod 400 /etc/group-
  chown root:root /etc/gshadow-
  chmod 600 /etc/gshadow-

  bitacora "Validar que no existan archivos con permisos 777" 1
  PERMISOS_777=$(df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0777)
  if [[ -n $PERMISOS_777 ]]; then
    df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0666 | xargs chmod 640
    bitacora "Se ha modificado los permisos" 2
  fi

  bitacora "Validar que no existan archivos o directorios sin propietarios" 1
  PROPIETARIOS=$(df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser)
  if [[ -n $PROPIETARIOS ]]; then
    df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser | xargs chown root:root
    bitacora "Se ha modificado el propietario" 2
  fi

  bitacora "Validar que no existan archivos o directorios sin grupo" 1
  NOGRUPOS=$(df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup)
  if [[ -n $PROPIETARIOS ]]; then
    df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup | xargs chgrp root
    bitacora "se ha modificado el grupo" 2
  fi
  
  bitacora "Auditar los ejecutables SUID" 1
  df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000
  bitacora "Auditar los ejecutables SGID" 2
  df --local -P | awk '{ if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
}
  

6.2_configuracion_usuarios_grupos() {
  bitacora "6.2_configuracion_usuarios_grupos()" 1
  bitacora "Configuracion de usuarios y grupos" 1
  bitacora "Validando si hay usuarios sin password" 2
  cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " no tiene password"}'
  
  bitacora "Heredadas en /etc/passwd" 2
  grep '^+:' /etc/passwd >> $BITACORA
  
  bitacora "Heredadas en /etc/shadow" 2
  grep '^+:' /etc/shadow >> $BITACORA
  
  bitacora "Heredadas en /etc/group" 2
  grep '^+:' /etc/group >> $BITACORA

  bitacora "Root debe ser el unico usuario con UID 0" 2
  respaldo /etc/passwd 
  
  for WRONG_USER in $(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | grep -v root); do 
    bitacora "Eliminando $WRONG_USER"  2
    sed -i "/$WRONG_USER/d" /etc/passwd; 
  done
  
  bitacora "Asegurar la integridad del PATH de root (profile)" 2
  if [ "$(echo $PATH | grep ::)" != "" ]; then
    bitacora "vacio en PATH (::)" 2
  fi
  
  if [ "$(echo $PATH | grep :$)" != "" ]; then
    bitacora "Revisando : en PATH" 2
  fi
  
  p=$(echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')
  set -- $p
  
  while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
      bitacora "PATH contiene ." 2
      shift
      continue
    fi
  
    if [ -d $1 ]; then
      dirperm=$(ls -ldH $1 | cut -f1 -d" ")
  
      if [ $(echo $dirperm | cut -c6) != "-" ]; then
        bitacora "Permisos de escritura de grupo establecidos en el directorio $1" 2
      fi
      
      if [ $(echo $dirperm | cut -c9) != "-" ]; then
        bitacora "Permisos de escritura de otros establecidos en el directorio $1" 2
      fi
      dirown=$(ls -ldH $1 | awk '{print $3}')
  
      if [ "$dirown" != "root" ] ; then
        bitacora "$1 no es propiedad de root" 2
      fi
    else
      bitacora "$1 no es un directorio" 2
    fi
    shift
  done
  
  bitacora "Asegurarse que todos los usuarios tengan su directorio en home." 1
  cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do 
    if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then 
      bitacora "El directorio home ($dir) para el usuario $user no existe.";  2
    fi; 
  done

  bitacora "Asegurarse que los permisos de las carpetas de los usuarios en home  sea de 750 o mas restrictiva" 1
  cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'|xargs chmod 750
  
  bitacora "Asegurarse que ningún usuario tenga archivos .forward" 1
  for dir in $(cat /etc/passwd | awk -F: '{ print $6 }'); do 
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then 
      bitacora "Archivo .forward encontrado en $dir/" 2
    fi; 
  done
  
  bitacora "Asegurarse que ningún usuario tenga archivos .netrc" 1
  for dir in $(cat /etc/passwd | awk -F: '{ print $6 }'); do 
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then 
      bitacora "Archivo .netrc encontrado en $dir/"  2
    fi; 
  done
  
  bitacora "Asegurarse que ningún usuario tenga archivos .rhosts" 1
  for dir in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'); do 
    for file in $dir/.rhosts; do 
      if [ ! -h "$file" -a -f "$file" ]; then 
        bitacora "Archivo .rhosts encontrado en $dir"  2
      fi 
    done 
  done
  
  bitacora "Asegurarse que todos los grupos de /etc/passwd existan en /etc/group" 1
  for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do 
    $(grep -q -P "^.*?:[^:]*:$i:" /etc/group)
    if [[ $(grep -q -P "^.*?:[^:]*:$i:" /etc/group) -ne 0 ]]; then 
      bitacora "Grupo $i esta referenciado en /etc/passwd pero no existe en /etc/group";  2
    fi 
  done
  
  bitacora "Asegurarse que no existan UIDs duplicados" 1
  cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do 
    [ -z "${x}" ] && break
    set - $x
    if [[ $1 -gt 1 ]]; then 
      users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
      bitacora "UID duplicado ($2): ${users}" 2
    fi 
  done
  
  bitacora "Asegurarse que no existan GIDs duplicados" 1
  cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do 
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then 
      groups=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs) 
      bitacora "GID duplicado ($2): ${groups}" 2
    fi
  done
  
  bitacora "Asegurarse que no existan nombres de usuarios duplicados" 1
  cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do 
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then 
      uids=$(awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs) 
      bitacora "Nombre de usuario duplicado ($2): ${uids}" 2 
    fi
  done 
  
  bitacora "Asegurarse que no existan nombres de grupos duplicados" 1
  cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do 
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then 
      gids=$(gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs) 
      bitacora "Nombre de grupo duplicado ($2): ${gids}" 2
    fi
  done
  
  bitacora "Validaciones Extras" 1
  bitacora "Instalacion de SUDO" 2
  if [[ $(rpm -qa | grep sudo ) ]]; then
    bitacora "instalando SUDO" 2
    yum install -y sudo
  else
    bitacora "SUDO esta instalado" 2
  fi
  
  bitacora "Permisos del archivo /etc/sudoers en 644" 2
  chmod 644 /etc/sudoers
  
  bitacora "Deshabilitar firewall local" 1
  systemctl disable --now firewalld
  
  bitacora "Eliminacion de emacs-filesystem" 2
  yum remove -y emacs-filesystem
}
  
bitacora "==============================================" 1
bitacora "======= Iniciando Proceso de Hardening =======" 1
1.1.1_eliminar_filesystems 2>> $BITACORA
1.1.1_modificar_fstab 2>> $BITACORA
1.1.1_operaciones_filesystems 2>> $BITACORA
1.2_revisar_suscripcion 2>> $BITACORA
1.3_checar_integridad_fs 2>> $BITACORA
1.4_configuraciones_seguras_boot 2>> $BITACORA
1.5_procesos_adicionales_hardening 2>> $BITACORA
1.6_configuraciones_mac_selinux 2>> $BITACORA
1.6_configuraciones_mac_extras 2>> $BITACORA
1.7_banners 2>> $BITACORA
1.8_actualizaciones_seguridad 2>> $BITACORA
2.1_servicios_inetd 2>> $BITACORA
2.2_servicios_proposito_especial 2>> $BITACORA
3.1_parametros_red 2>> $BITACORA
3.1_parametros_red_ipv6 2>> $BITACORA
3.4_configuracion_red 2>> $BITACORA
3.6_configuracion_auditd 2>> $BITACORA
3.6_reglas_audit 2>> $BITACORA
4.2_configuracion_logs 2>> $BITACORA
5.1_configuracion_cron 2>> $BITACORA
5.4._cuentas_y_ambiente 2>> $BITACORA
6.1_permisos_archivos_sistema 2>> $BITACORA
6.2_configuracion_usuarios_grupos 2>> $BITACORA
bitacora "======= Fin de Proceso de Hardening =======" 1
