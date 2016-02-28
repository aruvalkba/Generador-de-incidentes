#!/usr/bin/perl

use strict;
use warnings;
use 5.010;
use Getopt::Long qw(GetOptions);
use Pod::Usage;
use Data::Dumper;


    my ($help,$cont,$dir,$org,$log);
    my @batch;

    GetOptions(
        'help|h' 			=> 	\$help,
        'batch|b=s' 		=> 	\@batch,
        'continious|c' 		=> 	\$cont,
        'directory|d=s' 	=>	\$dir,
        'origin|o=s'		=>	\$org,
        'log|l=s'			=>	\$log,

    )or die "Modo de uso: perl generador.pl [-h|--help] [-b|--batch logfile1..] [-c|--continious] [-d|--directory path] [-o|--origin path] [-l|--log path]\n";
    
    pod2usage(-verbose => 2) if ($help);
     
    
    #if ($help) {
    #    help();
    #}
    #elsif(@batch){
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