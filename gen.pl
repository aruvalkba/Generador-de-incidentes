#!/usr/bin/perl

use strict;
#use warnings;

use Getopt::Long qw(GetOptions);	
use Pod::Usage;
use Data::Dumper;
use Linux::Inotify2;
use SnortUnified(qw(:ALL));
use Socket;

	#variables para las opciones del programa
    my ($help,$cont,$dir,$org,$log);
    my @batch;
    my ($dir_set, $dir_value, $ori_get, $ori_value, $logi_test, $logi_val);
    my $filetest;
    my $prueba;
    #se obtienen las opciones de la linea de comandos
    GetOptions(
        'help|h' 			=> 	\&help,
        'batch|b=s' 		=> 	\@batch,
        'continious|c' 		=> 	\&continious,
        'directory|d=s' 	=>	\&dir,
        'origin|o=s'		=>	\&org,
        'log|l=s'			=>	\&logi,

    )or die "Modo de uso: perl generador.pl [-h|--help] [-b|--batch logfile1..] [-c|--continious] [-d|--directory path] [-o|--origin path] [-l|--log path]\n";
    

    #if($dir){
    #    say $dir;
    #}
    #si se selecciona la opcion -h o --help se muestra la documentacion definida al final de este archivo
    
     
    
    #if(@batch){
    #    batch();
    #}

    sub help{
        print "

NOMBRE

    Generador de incidentes - obtiene el primer y ultimo evento de archivos unified2

SINOPSIS

    perl generador.pl [opciones] [archivo ...]
    
DESCRIPCION

    Este programa recibe como entrada uno o varios archivos unified2 
    para procesarlos y genera un nuevo archivo unifed2 que contendra 
    unicamente el primer y ultimo evento de un incidente de forma que
    se reduzca significativamente el tamano de cada archivo generado.
    Ademas genera un archivo en texto plano donde se almacenan el 
    numero de eventos por incidente. 


OPCIONES

  -h, --help

    Muestra la ayuda del programa        
    
  -b, --batch 

    Modo por lotes: procesa uno o varios archivos para obtener los 
    incidentes.

 -c- --continious

    El programa se ejecuta como un demonio del sistema y revisa de manera
    cotinua el directorio en busca de nuevos eventos en el archivo.


 -d, --directory

    Directorio en el cual se guardan los archivos generados

 -o, --origin

    Directorio que contiene los archivos unified2 a procesar

 -l, --log 
    
    Directorio que contiene las bitacoras de la ejecucion de la herramienta    



        ";
        exit();
    }    


    sub batch {

    }


    sub continious {
        my ($cont_set, $cont_val) = shift;
        if($cont_set){
            my $inotify = new Linux::Inotify2;

            my $dir = "./archivos";

            #$inotify->watch($dir, IN_CREATE, sub {
            #    my $event = shift;
            #    my $name = $event->fullname;
            #    print $name . "se ha creado un archivo";
            #});

            $inotify->watch($dir, IN_CREATE);
            print "hola";
            
            while(){
                my @eventos = $inotify->read;
                unless (@eventos > 0) {
                    print "read error $!";
                    last;
                }

                foreach my $event (@eventos){
                    my $name = $event->fullname;
                    print $event->name . " was created\n" if $event->IN_CREATE;
                    print $name . " ya fue creado\n" if $event->IN_CREATE;
                    prueba($name) if $event->IN_CREATE;
                    #print "holaprint - $name";
                    #print Dumper($event->fullname) . " was created\n" if $event->IN_CREATE;
                    #print $danfile $name if $event->IN_CREATE;
                }
            }
        }
        #print "$cont_set - $cont_val";
    }

    sub prueba {
        my ($prueba_val, $prueba_set) = @_;
        #print "1\t" . $prueba_val . "\t2\t" . $prueba_set . "\tEsta es una prueba\n";
        my $UF_DATA = openSnortUnified($prueba_val);
        my $record;
        my %eventos;
        my %contIPV4;
        my $eventos = {};
        my $filenametxt = "./continuo/procesado-continuo.txt";
        my $filenamelog = "./continuo/procesado-continuo.log";
        open(my $log, '>',$filenametxt) or die "No se abrio el archivo '$filenametxt' $!";
        print $log "Se ha iniciado la lectura del archivo";    
        open(my $u2, '>',$filenamelog) or die "No se abrio el archivo '$filenamelog' $!";
        binmode($u2); #la escritura se hace en modo binario
        my $localtime2 = localtime;
        while($record = readSnortUnified2Record()){
            #se guardan eventos IPV4 o IPV6 
            if($record->{'TYPE'} == 7 || $record->{'TYPE'} == 72){
                #si los valores del evento  estan en el hash se agrega como ultimo evento 
                if(exists $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}){
                    $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo'} = $record;
                    print $log "se agrego ultimo evento $localtime2\n";
                    #leemos el siguiente evento, el cual es el paquete asociado al evento anterior
                    my  $paq = readSnortUnified2Record();
                    #guardamos el ultimo evento
                    #se guarda el paquete del ultimo evento
                    $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paq'} = $paq;
                    print $log "se agrego ultimo paquete $localtime2\n";
                }
                #si las llaves del evento no estan en el hash, se agrega como primer evento
                elsif(!exists $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}){
                    $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primero'} = $record;
                    print $log "se agrego primer evento $localtime2\n";
                    #se guarda el paquete del primer evento
                    my  $paq = readSnortUnified2Record();
                    $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primer_paq'} = $paq;
                    print $log "se agrego primer paquete $localtime2\n";
                }
            }
        }
        closeSnortUnified();
        print $log "Se ha cerrado el archivo";
        foreach my $key(keys  %eventos){
            #pack al primer evento
            print $u2 pack('NN',$eventos{$key}{primero}{TYPE},$eventos{$key}{primero}{SIZE}).$eventos{$key}{primero}{raw_record};
            #pack al primer paquete
            print $u2 pack('NN',$eventos{$key}{primer_paq}{TYPE},$eventos{$key}{primer_paq}{SIZE}).$eventos{$key}{primer_paq}{raw_record};
            #pack al ultimo record
            print $u2 pack('NN',$eventos{$key}{ultimo}{TYPE},$eventos{$key}{ultimo}{SIZE}).$eventos{$key}{ultimo}{raw_record};
            #pack al ultimo paquete
            print $u2 pack('NN',$eventos{$key}{ultimo_paq}{TYPE},$eventos{$key}{ultimo_paq}{SIZE}).$eventos{$key}{ultimo_paq}{raw_record};            
        }
        close $u2;

        my $txtname = "./continuo/texto-claro.txt";
        open(my $txt, '>',$txtname) or die "No se abrio el archivo '$txtname' $!";
        print $txt "ID incidente \t|\t No. eventos\n\n ";
        foreach my $str(sort keys %contIPV4){ printf $txt "%i\n", $str, $contIPV4{$str} }
        #foreach my $str(sort keys %contIPVprueba $txt "%i\n", $str, $contIPV6{$str} }
        close $txt;
        close $log;
    }

    sub watch_new {
        my $e = shift;
        my $filecont = "continuo";
        open(my $danfile, ">>", $filecont) or die "No se pudo crear el archivo";
        print $danfile "New file or dir: " . $e->fullname . "\n";
        close($danfile);
    }

    sub dir {
        ($dir_set, $dir_value) = @_;
        #print $dir_value . "\n";
        mkdir $dir_value, 0777;

    }

    sub org {
        my ($ori_get, $ori_value) = @_;
        opendir(DIR, $ori_value) or die "Error no se puede abrir el directorio $ori_get";
        while(( $filetest = readdir(DIR))){
            if($filetest =~ /(.*log.*)/){
                my $rutarchivo = "./$ori_value/$filetest";

                my $record; #variable para cada evento IDS y paquete del archivo
                my $UF_DATA = openSnortUnified($rutarchivo); #se lee el archivo de snort
                
                my $filename = 'procesado.log';
                my $txtname = 'procesado.txt';
                my $logname = 'generador.log';
                my %eventos;
                my $eventos = {};
                my $primero;
                my $ultimo;
                my %contIPV4;
                my %contIPV6;
                my $pathdir = "./$dir_value/$filename";
                my $pathdir2 = "./$dir_value/$txtname";
                my $pathdir3 = "./$logi_val/$logname";
                #print $pathdir;
                #print $pathdir2;
                #apertura del nuevo archivo unified2
                my $localtime = localtime;

                open(my $u2, '>',$pathdir) or die "No se abrio el archivo '$filename' $!";
                binmode($u2); #la escritura se hace en modo binario
                
                open(my $log, '>',$pathdir3) or die "No se abrio el archivo '$filename' $!";
                print $log "Se ha iniciado la lectura del archivo";    
                   
                #mientras haya eventos en el archivo se leen
                while($record = readSnortUnified2Record()){
                    #se guardan eventos IPV4 o IPV6 
                    if($record->{'TYPE'} == 7 || $record->{'TYPE'} == 72){
                        #si los valores del evento  estan en el hash se agrega como ultimo evento 
                        if(exists $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}){
                            $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo'} = $record;
                            #$contIPV4{$_}++ if{$record->{'TYPE'}==7};
                            #$contIPV6{$_}++ if{$record->{'TYPE'}==72};
                
                                print $log "se agrego ultimo evento $localtime\n";
                
                            #leemos el siguiente evento, el cual es el paquete asociado al evento anterior
                            my  $paq = readSnortUnified2Record();
                            #guardamos el ultimo evento
                            #se guarda el paquete del ultimo evento
                            $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paq'} = $paq;
                
                                print $log "se agrego ultimo paquete $localtime\n";  
                
                        }
                        #si las llaves del evento no estan en el hash, se agrega como primer evento
                        elsif(!exists $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}){
                            $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primero'} = $record;
                
                                print $log "se agrego primer evento $localtime\n";
                
                            #se guarda el paquete del primer evento
                            my  $paq = readSnortUnified2Record();
                            $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primer_paq'} = $paq;
                
                                print $log "se agrego primer paquete $localtime\n";
                
                        }
                    }
                }
                closeSnortUnified();
                print $log "Se ha cerrado el archivo";
                foreach my $key(keys  %eventos){
                    #pack al primer evento
                    print $u2 pack('NN',$eventos{$key}{primero}{TYPE},$eventos{$key}{primero}{SIZE}).$eventos{$key}{primero}{raw_record};
                    #pack al primer paquete
                    print $u2 pack('NN',$eventos{$key}{primer_paq}{TYPE},$eventos{$key}{primer_paq}{SIZE}).$eventos{$key}{primer_paq}{raw_record};

                    #pack al ultimo record
                    print $u2 pack('NN',$eventos{$key}{ultimo}{TYPE},$eventos{$key}{ultimo}{SIZE}).$eventos{$key}{ultimo}{raw_record};
                    #pack al ultimo paquete
                    print $u2 pack('NN',$eventos{$key}{ultimo_paq}{TYPE},$eventos{$key}{ultimo_paq}{SIZE}).$eventos{$key}{ultimo_paq}{raw_record};
                    
                    
                }
                close $u2;

                open(my $txt, '>',$pathdir2) or die "No se abrio el archivo '$txtname' $!";
                print $txt "ID incidente \t|\t No. eventos\n\n ";
                foreach my $str(sort keys %contIPV4){ printf $txt "%i\n", $str, $contIPV4{$str} }
                #foreach my $str(sort keys %contIPVprueba $txt "%i\n", $str, $contIPV6{$str} }
                close $txt;
                close $log;
            }       
        }
        closedir(DIR);
    }


    sub logi {
        ($logi_test, $logi_val) = @_;
        print $logi_val;
    }
	
#print "hola";

#print $cont;

#foreach(@arrayfile){
#    print unpack('N',$_);
#}    

sub make_hex() {
		my $data = shift;
		return unpack("h* ",$data);
}

sub make_ascii() {
		my $data = shift;
		print $data;
		my $asc = unpack('a*', $data);
		$asc =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
		return $asc;
}

__END__
    
=pod

=head1 NOMBRE

    Generador de incidentes - obtiene el primer y ultimo evento de archivos unified2

=head1 SINOPSIS

    perl generador.pl [opciones] [archivo ...]
    
=head1 DESCRIPCION

    Este programa recibe como entrada uno o varios archivos unified2 
    para procesarlos y genera un nuevo archivo unifed2 que contendra 
    unicamente el primer y ultimo evento de un incidente de forma que
    se reduzca significativamente el tamano de cada archivo generado.
    Ademas genera un archivo en texto plano donde se almacenan el 
    numero de eventos por incidente. 


=head1 OPCIONES

=head2  -h, --help

    Muestra la ayuda del programa        
    
=head2  -b, --batch 

    Modo por lotes: procesa uno o varios archivos para obtener los 
    incidentes.

=head2 -c- --continious

    El programa se ejecuta como un demonio del sistema y revisa de manera
    cotinua el directorio en busca de nuevos eventos en el archivo.


=head2 -d, --directory

    Directorio en el cual se guardan los archivos generados

=head2 -o, --origin

    Directorio que contiene los archivos unified2 a procesar

=head2 -l, --log 
    
    Directorio que contiene las bitacoras de la ejecucion de la herramienta    

=cut
