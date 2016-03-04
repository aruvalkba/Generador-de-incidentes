#!/usr/bin/perl

use strict;
use warnings;
use 5.010;
use Getopt::Long qw(GetOptions);    
use Pod::Usage;
#use Data::Dumper;
use SnortUnified(qw(:ALL));
use Socket;

	#variables para las opciones del programa
    my ($help,$cont,$dir,$org,$log);
    my @batch;

    #se obtienen las opciones de la linea de comandos
    GetOptions(
        'help|h' 			=> 	\$help,
        'batch|b=s' 		=> 	\@batch,
        'continious|c' 		=> 	\$cont,
        'directory|d=s' 	=>	\$dir,
        'origin|o=s'		=>	\$org,
        'log|l=s'			=>	\$log,

    )or die "Modo de uso: perl generador.pl [-h|--help] [-b|--batch logfile1..] [-c|--continious] [-d|--directory path] [-o|--origin path] [-l|--log path]\n";
    
    #si se selecciona la opcion -h o --help se muestra la documentacion definida al final de este archivo
    pod2usage(-verbose => 2) if ($help);
     
    
    #if(@batch){
    #    batch();
    #}
    

    sub batch {

    }


    sub continious {

    }



    sub directory {

    }


    sub origin {

    }


    sub log {

    }

    my $record; #variable para cada evento IDS y paquete del archivo
	my $UF_DATA = openSnortUnified(shift); #se lee el archivo de snort
    my $filename = 'procesado.log';
    my $txtname = 'procesado.txt';
    my %eventos;
    my $eventos = {};
    #my $primero;
    #my $ultimo;
    my %evento_grupo;
    my $evento_grupo = {};

    #apertura del nuevo archivo unified2
    open(my $u2, '>',$filename) or die "No se abrio el archivo '$filename' $!";
    binmode($u2); #la escritura se hace en modo binario

    #mientras haya eventos en el archivo se leen
	while($record = readSnortUnified2Record()){
        my $id=1;
        my $total=1;
        #se guardan eventos IPV4 o IPV6 
        if($record->{'TYPE'} == 7 || $record->{'TYPE'} == 72){
            #si los valores del evento  estan en el hash se agrega como ultimo evento 
            if(exists $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}){
                $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo'} = $record;
                #print "se agrego ultimo evento\n";

                #se agrega un identificador al grupo de eventos que comparten la misma IP de origen,
                #el protocolo y el tipo de alerta
                $evento_grupo{'id'} = $id;
                $evento_grupo{'total'} = $total++;

                #leemos el siguiente evento, el cual es el paquete asociado al evento anterior
                my  $paq = readSnortUnified2Record();
                #se guarda el paquete del ultimo evento
                $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'ultimo_paq'} = $paq;
                #print "se agrego ultimo paquete\n";  
            }
            #si las llaves del evento no estan en el hash, se agrega como primer evento
            elsif(!exists $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}){
                $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primero'} = $record;
                #print "se agrego primer evento\n";
                $evento_grupo{'id'} = $id++;
                $evento_grupo{'total'} = $total;

                #se guarda el paquete del primer evento
                my  $paq = readSnortUnified2Record();
                $eventos{$record->{'sig_id'},$record->{'sip'},$record->{'protocol'}}{'primer_paq'} = $paq;
                #print "se agrego primer paquete\n";
            }       
        }
    }   

closeSnortUnified();
#print Dumper(%eventos);

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

open(my $txt, '>',$txtname) or die "No se abrio el archivo '$txtname' $!";
print $txt "ID incidente \t|\t No. eventos\n\n ";
foreach my $key(keys %evento_grupo){ print "$evento_grupo{$key}\n";}
close $txt;

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