#!/bin/bash
# Placeholder for CI build. Not part of the challenge.
#
# Author: Kirill Timofeev <kt97679@gmail.com>

set -u # non initialized variable is an error

# 2 signals are used: SIGUSR1 to decrease delay after level up and SIGUSR2 to quit
# they are sent to all instances of this script
# because of that we should process them in each instance
# in this instance we are ignoring both signals
trap '' SIGUSR1 SIGUSR2

# Those are commands sent to controller by key press processing code
# In controller they are used as index to retrieve actual functuon from array
QUIT=0
RIGHT=1
LEFT=2
ROTATE=3
DOWN=4
DROP=5
TOGGLE_HELP=6
TOGGLE_NEXT=7
TOGGLE_COLOR=8

DELAY=1          # initial delay between piece movements
DELAY_FACTOR=0.8 # this value controld delay decrease for each level up

# color codes
RED=1
GREEN=2
YELLOW=3
BLUE=4
FUCHSIA=5
CYAN=6
WHITE=7

# Location and size of playfield, color of border
PLAYFIELD_W=10
PLAYFIELD_H=20
PLAYFIELD_X=30
PLAYFIELD_Y=1
BORDER_COLOR=$YELLOW

# Location and color of score information
SCORE_X=1
SCORE_Y=2
SCORE_COLOR=$GREEN

# Location and color of help information
HELP_X=58
HELP_Y=1
HELP_COLOR=$CYAN

# Next piece location
NEXT_X=14
NEXT_Y=11

# Location of "game over" in the end of the game
GAMEOVER_X=1
GAMEOVER_Y=$((PLAYFIELD_H + 3))

# Intervals after which game level (and game speed) is increased
LEVEL_UP=20

colors=($RED $GREEN $YELLOW $BLUE $FUCHSIA $CYAN $WHITE)

no_color=true    # do we use color or not
showtime=true    # controller runs while this flag is true
empty_cell=" ."  # how we draw empty cell
filled_cell="[]" # how we draw filled cell

score=0           # score variable initialization
level=1           # level variable initialization
lines_completed=0 # completed lines counter initialization

# screen_buffer is variable, that accumulates all screen changes
# this variable is printed in controller once per game cycle
puts() {
    screen_buffer+=${1}
}

# move cursor to (x,y) and print string
# (1,1) is upper left corner of the screen
xyprint() {
    puts "\033[${2};${1}H${3}"
}

show_cursor() {
    echo -ne "\033[?25h"
}

hide_cursor() {
    echo -ne "\033[?25l"
}

# foreground color
set_fg() {
    $no_color && return
    puts "\033[3${1}m"
}

# background color
set_bg() {
    $no_color && return
    puts "\033[4${1}m"
}

reset_colors() {
    puts "\033[0m"
}

set_bold() {
    puts "\033[1m"
}

# playfield is 1-dimensional array, data is stored as follows:
# [ a11, a21, ... aX1, a12, a22, ... aX2, ... a1Y, a2Y, ... aXY]
#   |<  1st line   >|  |<  2nd line   >|  ... |<  last line  >|
# X is PLAYFIELD_W, Y is PLAYFIELD_H
# each array element contains cell color value or -1 if cell is empty
redraw_playfield() {
    local j i x y xp yp

    ((xp = PLAYFIELD_X))
    for ((y = 0; y < PLAYFIELD_H; y++)) {
        ((yp = y + PLAYFIELD_Y))
        ((i = y * PLAYFIELD_W))
        xyprint $xp $yp ""
        for ((x = 0; x < PLAYFIELD_W; x++)) {
            ((j = i + x))
            if ((${play_field[$j]} == -1)) ; then
                puts "$empty_cell"
            else
                set_fg ${play_field[$j]}
                set_bg ${play_field[$j]}
                puts "$filled_cell"
                reset_colors
            fi
        }
    }
}

update_score() {
    # Arguments: 1 - number of completed lines
    ((lines_completed += $1))
    # Unfortunately I don't know scoring algorithm of original tetris
    # Here score is incremented with squared number of lines completed
    # this seems reasonable since it takes more efforts to complete several lines at once
    ((score += ($1 * $1)))
    if (( score > LEVEL_UP * level)) ; then          # if level should be increased
        ((level++))                                  # increment level
    fi
    set_bold
    set_fg $SCORE_COLOR
    xyprint $SCORE_X $SCORE_Y         "Lines completed: $lines_completed"
    xyprint $SCORE_X $((SCORE_Y + 1)) "Level:           $level"
    xyprint $SCORE_X $((SCORE_Y + 2)) "Score:           $score"
    reset_colors
}

help=(
"  Use cursor keys"
"       or"
"      s: up"
"a: left,  d: right"
"    space: drop"
"      q: quit"
"  c: toggle color"
"n: toggle show next"
"h: toggle this help"
)

help_on=-1 # if this flag is 1 help is shown

toggle_help() {
    local i s

    set_bold
    set_fg $HELP_COLOR
    for ((i = 0; i < ${#help[@]}; i++ )) {
        # ternary assignment: if help_on is 1 use string as is, otherwise substitute all characters with spaces
        ((help_on == 1)) && s="${help[i]}" || s="${help[i]//?/ }"
        xyprint $HELP_X $((HELP_Y + i)) "$s"
    }
    ((help_on = -help_on))
    reset_colors
}

# this array holds all possible pieces that can be used in the game
# each piece consists of 4 cells
# each string is sequence of relative xy coordinates for different orientations
# depending on piece symmetry there can be 1, 2 or 4 orientations
piece=(
"00011011"                         # square piece
"0212223210111213"                 # line piece
"0001111201101120"                 # S piece
"0102101100101121"                 # Z piece
"01021121101112220111202100101112" # L piece
"01112122101112200001112102101112" # inverted L piece
"01111221101112210110112101101112" # T piece
)

draw_piece() {
    # Arguments:
    # 1 - x, 2 - y, 3 - type, 4 - rotation, 5 - cell content
    local i x y

    # loop through piece cells: 4 cells, each has 2 coordinates
    for ((i = 0; i < 8; i += 2)) {
        # relative coordinates are retrieved based on orientation and added to absolute coordinates
        ((x = $1 + ${piece[$3]:$((i + $4 * 8 + 1)):1} * 2))
        ((y = $2 + ${piece[$3]:$((i + $4 * 8)):1}))
        xyprint $x $y "$5"
    }
}

next_piece=0
next_piece_rotation=0
next_piece_color=0

next_on=1 # if this flag is 1 next piece is shown

draw_next() {
    # Arguments: 1 - string to draw single cell
    ((next_on == -1)) && return
    draw_piece $NEXT_X $NEXT_Y $next_piece $next_piece_rotation "$1"
}

clear_next() {
    draw_next "${filled_cell//?/ }"
}

show_next() {
    set_fg $next_piece_color
    set_bg $next_piece_color
    draw_next "${filled_cell}"
    reset_colors
}

toggle_next() {
    case $next_on in
        1) clear_next; next_on=-1 ;;
        -1) next_on=1; show_next ;;
    esac
}

draw_current() {
    # Arguments: 1 - string to draw single cell
    # factor 2 for x because each cell is 2 characters wide
    draw_piece $((current_piece_x * 2 + PLAYFIELD_X)) $((current_piece_y + PLAYFIELD_Y)) $current_piece $current_piece_rotation "$1"
}

show_current() {
    set_fg $current_piece_color
    set_bg $current_piece_color
    draw_current "${filled_cell}"
    reset_colors
}

clear_current() {
    draw_current "${empty_cell}"
}

new_piece_location_ok() {
    # Arguments: 1 - new x coordinate of the piece, 2 - new y coordinate of the piece
    # test if piece can be moved to new location
    local j i x y x_test=$1 y_test=$2

    for ((j = 0, i = 1; j < 8; j += 2, i = j + 1)) {
        ((y = ${piece[$current_piece]:$((j + current_piece_rotation * 8)):1} + y_test)) # new y coordinate of piece cell
        ((x = ${piece[$current_piece]:$((i + current_piece_rotation * 8)):1} + x_test)) # new x coordinate of piece cell
        ((y < 0 || y >= PLAYFIELD_H || x < 0 || x >= PLAYFIELD_W )) && return 1         # check if we are out of the play field
        ((${play_field[y * PLAYFIELD_W + x]} != -1 )) && return 1                       # check if location is already ocupied
    }
    return 0
}

get_random_next() {
    # next piece becomes current
    current_piece=$next_piece
    current_piece_rotation=$next_piece_rotation
    current_piece_color=$next_piece_color
    # place current at the top of play field, approximately at the center
    ((current_piece_x = (PLAYFIELD_W - 4) / 2))
    ((current_piece_y = 0))
    # check if piece can be placed at this location, if not - game over
    new_piece_location_ok $current_piece_x $current_piece_y || cmd_quit
    show_current

    clear_next
    # now let's get next piece
    ((next_piece = RANDOM % ${#piece[@]}))
    ((next_piece_rotation = RANDOM % (${#piece[$next_piece]} / 8)))
    ((next_piece_color = RANDOM % ${#colors[@]}))
    show_next
}

draw_border() {
    local i x1 x2 y

    set_bold
    set_fg $BORDER_COLOR
    ((x1 = PLAYFIELD_X - 2))               # 2 here is because border is 2 characters thick
    ((x2 = PLAYFIELD_X + PLAYFIELD_W * 2)) # 2 here is because each cell on play field is 2 characters wide
    for ((i = 0; i < PLAYFIELD_H + 1; i++)) {
        ((y = i + PLAYFIELD_Y))
        xyprint $x1 $y "<|"
        xyprint $x2 $y "|>"
    }

    ((y = PLAYFIELD_Y + PLAYFIELD_H))
    for ((i = 0; i < PLAYFIELD_W; i++)) {
        ((x1 = i * 2 + PLAYFIELD_X)) # 2 here is because each cell on play field is 2 characters wide
        xyprint $x1 $y '=='
        xyprint $x1 $((y + 1)) "\/"
    }
    reset_colors
}

toggle_color() {
    $no_color && no_color=false || no_color=true
    show_next
    update_score 0
    toggle_help
    toggle_help
    draw_border
    redraw_playfield
    show_current
}

init() {
    local i x1 x2 y

    # playfield is initialized with -1s (empty cells)
    for ((i = 0; i < PLAYFIELD_H * PLAYFIELD_W; i++)) {
        play_field[$i]=-1
    }

    clear
    hide_cursor
    get_random_next
    get_random_next
    toggle_color
}

# this function runs in separate process
# it sends DOWN commands to controller with appropriate delay
ticker() {
    # on SIGUSR2 this process should exit
    trap exit SIGUSR2
    # on SIGUSR1 delay should be decreased, this happens during level ups
    trap 'DELAY=$(awk "BEGIN {print $DELAY * $DELAY_FACTOR}")' SIGUSR1

    while true ; do echo -n $DOWN; sleep $DELAY; done
}

# this function processes keyboard input
reader() {
    trap exit SIGUSR2 # this process exits on SIGUSR2
    trap '' SIGUSR1   # SIGUSR1 is ignored
    local -u key a='' b='' cmd esc_ch=$'\x1b'
    # commands is associative array, which maps pressed keys to commands, sent to controller
    declare -A commands=([A]=$ROTATE [C]=$RIGHT [D]=$LEFT
        [_S]=$ROTATE [_A]=$LEFT [_D]=$RIGHT
        [_]=$DROP [_Q]=$QUIT [_H]=$TOGGLE_HELP [_N]=$TOGGLE_NEXT [_C]=$TOGGLE_COLOR)

    while read -s -n 1 key ; do
        case "$a$b$key" in
            "${esc_ch}["[ACD]) cmd=${commands[$key]} ;; # cursor key
            *${esc_ch}${esc_ch}) cmd=$QUIT ;;           # exit on 2 escapes
            *) cmd=${commands[_$key]:-} ;;              # regular key. If space was pressed $key is empty
        esac
        a=$b   # preserve previous keys
        b=$key
        [ -n "$cmd" ] && echo -n "$cmd"
    done
}

# this function updates occupied cells in play_field array after piece is dropped
flatten_playfield() {
    local i j k x y
    for ((i = 0, j = 1; i < 8; i += 2, j += 2)) {
        ((y = ${piece[$current_piece]:$((i + current_piece_rotation * 8)):1} + current_piece_y))
        ((x = ${piece[$current_piece]:$((j + current_piece_rotation * 8)):1} + current_piece_x))
        ((k = y * PLAYFIELD_W + x))
        play_field[$k]=$current_piece_color
    }
}

# this function goes through play_field array and eliminates lines without empty sells
process_complete_lines() {
    local j i complete_lines
    ((complete_lines = 0))
    for ((j = 0; j < PLAYFIELD_W * PLAYFIELD_H; j += PLAYFIELD_W)) {
        for ((i = j + PLAYFIELD_W - 1; i >= j; i--)) {
            ((${play_field[$i]} == -1)) && break # empty cell found
        }
        ((i >= j)) && continue # previous loop was interrupted because empty cell was found
        ((complete_lines++))
        # move lines down
        for ((i = j - 1; i >= 0; i--)) {
            play_field[$((i + PLAYFIELD_W))]=${play_field[$i]}
        }
        # mark cells as free
        for ((i = 0; i < PLAYFIELD_W; i++)) {
            play_field[$i]=-1
        }
    }
    return $complete_lines
}

process_fallen_piece() {
    flatten_playfield
    process_complete_lines && return
    update_score $?
    redraw_playfield
}

move_piece() {
# arguments: 1 - new x coordinate, 2 - new y coordinate
# moves the piece to the new location if possible
    if new_piece_location_ok $1 $2 ; then # if new location is ok
        clear_current                     # let's wipe out piece current location
        current_piece_x=$1                # update x ...
        current_piece_y=$2                # ... and y of new location
        show_current                      # and draw piece in new location
        return 0                          # nothing more to do here
    fi                                    # if we could not move piece to new location
    (($2 == current_piece_y)) && return 0 # and this was not horizontal move
    process_fallen_piece                  # let's finalize this piece
    get_random_next                       # and start the new one
    return 1
}

cmd_right() {
    move_piece $((current_piece_x + 1)) $current_piece_y
}

cmd_left() {
    move_piece $((current_piece_x - 1)) $current_piece_y
}

cmd_rotate() {
    local available_rotations old_rotation new_rotation

    available_rotations=$((${#piece[$current_piece]} / 8))            # number of orientations for this piece
    old_rotation=$current_piece_rotation                              # preserve current orientation
    new_rotation=$(((old_rotation + 1) % available_rotations))        # calculate new orientation
    current_piece_rotation=$new_rotation                              # set orientation to new
    if new_piece_location_ok $current_piece_x $current_piece_y ; then # check if new orientation is ok
        current_piece_rotation=$old_rotation                          # if yes - restore old orientation
        clear_current                                                 # clear piece image
        current_piece_rotation=$new_rotation                          # set new orientation
        show_current                                                  # draw piece with new orientation
    else                                                              # if new orientation is not ok
        current_piece_rotation=$old_rotation                          # restore old orientation
    fi
}

cmd_down() {
    move_piece $current_piece_x $((current_piece_y + 1))
}

cmd_drop() {
    # move piece all way down
    # this is example of do..while loop in bash
    # loop body is empty
    # loop condition is done at least once
    # loop runs until loop condition would return non zero exit code
    while move_piece $current_piece_x $((current_piece_y + 1)) ; do : ; done
}

cmd_quit() {
    showtime=false                               # let's stop controller ...
    xyprint $GAMEOVER_X $GAMEOVER_Y "Game over!"
    echo -e "$screen_buffer"                     # ... and print final message
}

controller() {
    # SIGUSR1 and SIGUSR2 are ignored
    trap '' SIGUSR1 SIGUSR2
    local cmd commands

    # initialization of commands array with appropriate functions
    commands[$QUIT]=cmd_quit
    commands[$RIGHT]=cmd_right
    commands[$LEFT]=cmd_left
    commands[$ROTATE]=cmd_rotate
    commands[$DOWN]=cmd_down
    commands[$DROP]=cmd_drop
    commands[$TOGGLE_HELP]=toggle_help
    commands[$TOGGLE_NEXT]=toggle_next
    commands[$TOGGLE_COLOR]=toggle_color

    init

    while $showtime; do           # run while showtime variable is true, it is changed to false in cmd_quit function
        echo -ne "$screen_buffer" # output screen buffer ...
        screen_buffer=""          # ... and reset it
        read -s -n 1 cmd          # read next command from stdout
        ${commands[$cmd]}         # run command
    done
}

stty_g=`stty -g` # let's save terminal state

# output of ticker and reader is joined and piped into controller
(
    ticker & # ticker runs as separate process
    reader
)|(
    controller
)

show_cursor
stty $stty_g # let's restore terminal state
