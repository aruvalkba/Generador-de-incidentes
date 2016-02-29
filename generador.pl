#!/usr/bin/perl

use strict;
use warnings;
use 5.010;
use Getopt::Long qw(GetOptions);	
use Pod::Usage;
use Data::Dumper;
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
        'directory|d=s' 	=>	\&directory,
        'origin|o=s'		=>	\$org,
        'log|l=s'			=>	\$log,

    )or die "Modo de uso: perl generador.pl [-h|--help] [-b|--batch logfile1..] [-c|--continious] [-d|--directory path] [-o|--origin path] [-l|--log path]\n";
    

    #if($dir){
    #    say $dir;
    #}
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
        my ($dir_name, $dir_value) = @_;
        print $dir_value . "\n";
        mkdir $dir_value, 0777;
    }


    sub origin {

    }


    sub log {

    }

    my $record; #variable para cada evento IDS y paquete del archivo
    my $UF_DATA = openSnortUnified(shift); #se lee el archivo de snort

    #se muestra en pantalla el contenido del archivo
    while(my $record = readSnortUnified2Record()){
        print "record type " . $record->{'TYPE'} . " is " . $UNIFIED2_TYPES->{$record->{'TYPE'}} . "\n";
        print "sip " . $record->{'sip'} . "\n" if defined $record->{'sip'};
        print "protocol " . $record->{'protocol'} . "\n" if defined $record->{'protocol'};
        print "event_id " . $record->{'event_id'} . "\n" if defined $record->{'event_id'};
        foreach my $field ( @{$record->{'FIELDS'}} ){

            if ($field ne 'pkt' && $field ne 'data_blob'){
                print("Campo " . $field . " : " . $record->{$field} . "\n");
            }
            else{
                print "data_blob\n";
                print("====================== ASCII\n");
                #my $valmake =  make_ascii($record->{'data_blob'}) . "\n";
                print $record->{'data_blob'} if defined $record->{'data_blob'};
                #print $valmake;
                }
        }
    }
closeSnortUnified();

    

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
