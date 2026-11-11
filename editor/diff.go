package editor

import (
	"strconv"
	"strings"
)

func ApplyDiff(oldContents, diff string) (string, error) {
	// There is likely a much more optimized way of applying diff --
	// Maybe dealing with the lines in-place and keeping track of index adjustments

	// Doesn't handle issues related to new line at end of file
	oldLines := strings.Split(oldContents, "\n")
	diffLines := strings.Split(diff, "\n")

	lineI := -1
	diffI := -1
	state := "want@"
	newContentsSlice := []string{}
	nextDiffIndex := -1
	for i := 0; i < 1000000; i++ {
		if state == "want@" {
			diffI++
			if diffI >= len(diffLines) {
				state = "doneDiff"
				continue
			}
			if !strings.HasPrefix(diffLines[diffI], "@@") {
				continue
			}
			nextDiffIndex = parseFirstNumber(diffLines[diffI]) - 1
			// log.Printf("FIRST NUMBER IS %d", nextDiffIndex)
			state = "getToNextIndex"
		} else if state == "getToNextIndex" {
			lineI++
			if lineI >= len(oldLines) {
				break
			}

			// this case only happens on first pass? or of there are adjacent chinks?
			if lineI == nextDiffIndex {
				lineI -= 1
				state = "in@"
				continue
			}
			newContentsSlice = append(newContentsSlice, oldLines[lineI])
			// -1 works because chunks can't be adjacent?
			if lineI == nextDiffIndex-1 {
				state = "in@"
				// if diffI >= len(diffLines) {
				//     state = "doneDiff"
				//     continue
				// }
			}
		} else if state == "in@" {
			diffI++
			if diffI >= len(diffLines) {
				state = "doneDiff"
				continue
			}
			if strings.HasPrefix(diffLines[diffI], "-") {
				lineI++
				if lineI >= len(oldLines) {
					break
				}
				// don't add
				// you could check that the removed lines match
				// possibly optimize diff to not include the line removed, just the "-"?
			} else if strings.HasPrefix(diffLines[diffI], "+") {
				newContentsSlice = append(newContentsSlice, diffLines[diffI][1:])
			} else if strings.HasPrefix(diffLines[diffI], "@@") {
				nextDiffIndex = parseFirstNumber(diffLines[diffI]) - 1
				state = "getToNextIndex"
			} else {
				lineI++
				if lineI >= len(oldLines) {
					break
				}
				// you could check that the lines match
				newContentsSlice = append(newContentsSlice, oldLines[lineI])
			}
		} else if state == "doneDiff" {
			lineI++
			if lineI >= len(oldLines) {
				break
			}
			newContentsSlice = append(newContentsSlice, oldLines[lineI])
		}
	}
	if state == "want@" {
		return oldContents, nil
	}
	return strings.Join(newContentsSlice, "\n"), nil
}

func parseFirstNumber(s string) int {
	numb := ""
	inNumber := false
	for _, c := range s {
		if inNumber {
			if c >= 48 && c <= 57 {
				numb += string(c)
			} else {
				break
			}
		} else {
			if c >= 48 && c <= 57 {
				numb += string(c)
				inNumber = true
			}
		}
	}
	if len(numb) > 10 {
		numb = numb[0:10]
	}
	n, _ := strconv.Atoi(numb)
	return n
}
