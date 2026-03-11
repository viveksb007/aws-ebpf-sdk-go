// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package elfparser

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

var (
	MAP_SECTION_INDEX = 8
	MAP_TYPE_1        = int(constdef.BPF_MAP_TYPE_LRU_HASH.Index())
	MAP_KEY_SIZE_1    = 16
	MAP_VALUE_SIZE_1  = 4
	MAP_ENTRIES_1     = 65536
	MAP_FLAGS_1       = 0
)

type testMocks struct {
	path       string
	ctrl       *gomock.Controller
	ebpf_progs *mock_ebpf_progs.MockBpfProgAPIs
	ebpf_maps  *mock_ebpf_maps.MockBpfMapAPIs
}

func setup(t *testing.T, testPath string) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       testPath,
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockBpfProgAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockBpfMapAPIs(ctrl),
	}
}

func TestLoad(t *testing.T) {
	progtests := []struct {
		name        string
		elfFileName string
		wantMap     int
		wantProg    int
	}{
		{
			name:        "Test Load ELF",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			wantMap:     3,
			wantProg:    3,
		},
		{
			name:        "Test Load ELF without reloc",
			elfFileName: "../../test-data/tc.bpf.elf",
			wantMap:     0,
			wantProg:    1,
		},
		{
			name:        "Missing prog data",
			elfFileName: "../../test-data/test.map.bpf.elf",
			wantMap:     1,
			wantProg:    0,
		},
		{
			name:        "Test Load ELF with subprograms",
			elfFileName: "../../test-data/tc.subprog.bpf.elf",
			wantMap:     1,
			wantProg:    1,
		},
		{
			name:        "Test Load ELF with chained subprograms",
			elfFileName: "../../test-data/tc.subprog_chain.bpf.elf",
			wantMap:     1,
			wantProg:    1,
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")
			loadedProgs, loadedMaps, err := elfLoader.doLoadELF(BpfCustomData{})
			assert.NoError(t, err)
			assert.Equal(t, tt.wantProg, len(loadedProgs))
			assert.Equal(t, tt.wantMap, len(loadedMaps))
		})
	}
}

func TestParseSection(t *testing.T) {

	tests := []struct {
		name        string
		elfFileName string
		want        []string
		wantErr     error
	}{
		{
			name:        "Test license section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        []string{"GPL\u0000"},
		},
		{
			name:        "Missing license section",
			elfFileName: "../../test-data/test_license.bpf.elf",
			want:        []string{},
			wantErr:     errors.New("license missing in elf file"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotLicense []string
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotLicense = append(gotLicense, elfLoader.license)
				assert.Equal(t, tt.want, gotLicense)
			}
		})
	}

	maptests := []struct {
		name        string
		elfFileName string
		want        int
		wantErr     error
	}{
		{
			name:        "Test map section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			//Assumption is mapindex is always 8 based on elf data we are using. This can be any non-zero.
			want: MAP_SECTION_INDEX,
		},
		{
			name:        "Missing map section",
			elfFileName: "../../test-data/tc.bpf.elf",
			want:        0,
			wantErr:     nil,
		},
	}

	for _, tt := range maptests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotMapIndex := elfLoader.mapSectionIndex
				assert.Equal(t, tt.want, gotMapIndex)
			}
		})
	}

	texttests := []struct {
		name            string
		elfFileName     string
		wantTextSection bool
		wantTextRelo    bool
	}{
		{
			name:            "Empty .text section in regular ELF",
			elfFileName:     "../../test-data/tc.ingress.bpf.elf",
			wantTextSection: true,  // clang always emits a .text section
			wantTextRelo:    false, // but no .rel.text for regular ELFs
		},
		{
			name:            "Has .text section with subprograms",
			elfFileName:     "../../test-data/tc.subprog.bpf.elf",
			wantTextSection: true,
			wantTextRelo:    true, // has .rel.text for map relocation in subprogram
		},
	}

	for _, tt := range texttests {
		t.Run(tt.name, func(t *testing.T) {
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			assert.NoError(t, err)

			if tt.wantTextSection {
				assert.NotNil(t, elfLoader.textSection)
				assert.NotEqual(t, -1, elfLoader.textSectionIndex)
			} else {
				assert.Nil(t, elfLoader.textSection)
				assert.Equal(t, -1, elfLoader.textSectionIndex)
			}

			if tt.wantTextRelo {
				assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])
			}
		})
	}

	progtests := []struct {
		name        string
		elfFileName string
		want        []string
		wantErr     error
	}{
		{
			name:        "Test prog section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        []string{"tc_cls", "kprobe/nf_ct_delete", "tracepoint/sched/sched_process_fork"},
		},
		{
			// The elf file has supported and non-supported progs so we skip non-supported.
			name:        "Test unsupported prog section",
			elfFileName: "../../test-data/tc.bpf.elf",
			want:        []string{"tc_cls"},
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {
			var gotProgNames []string
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotProgSections := elfLoader.progSectionMap
				for _, progEntry := range gotProgSections {
					gotProgNames = append(gotProgNames, progEntry.progSection.Name)
				}
				sort.Strings(tt.want)
				sort.Strings(gotProgNames)
				assert.Equal(t, tt.want, gotProgNames)
			}
		})
	}

	reloctests := []struct {
		name        string
		elfFileName string
		expectList  []string
		want        int
		wantErr     error
	}{
		{
			name:        "Test reloc flow",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			expectList:  []string{"kprobe", "tc_cls", "tracepoint", "xdp"},
			want:        2,
			wantErr:     nil,
		},
		{
			name:        "Validate elf file without reloc requirement",
			elfFileName: "../../test-data/tc.bpf.elf",
			expectList:  []string{"kprobe", "tc_cls", "tracepoint", "xdp"},
			want:        0,
			wantErr:     nil,
		},
	}

	for _, tt := range reloctests {
		t.Run(tt.name, func(t *testing.T) {
			var gotSupportedType []string
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for _, r := range elfLoader.reloSectionMap {
					if contains(tt.expectList, r.Name) {
						gotSupportedType = append(gotSupportedType, r.Name)
					}
				}
				assert.Equal(t, tt.want, len(gotSupportedType))
			}
		})
	}
}

func contains(expectedList []string, expectedStr string) bool {
	for _, str := range expectedList {
		if strings.Contains(expectedStr, str) {
			return true
		}
	}
	return false
}

func TestParseMap(t *testing.T) {
	maptests := []struct {
		name        string
		elfFileName string
		want        int
		wantErr     error
	}{
		{
			name:        "Missing map section",
			elfFileName: "../../test-data/tc.bpf.elf",
			want:        0,
			wantErr:     nil,
		},
		{
			name:        "Test map data",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        3,
			wantErr:     nil,
		},
	}

	for _, tt := range maptests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			assert.NoError(t, err)
			mapData, err := elfLoader.parseMap(BpfCustomData{})
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				mapCount := len(mapData)
				assert.Equal(t, tt.want, mapCount)
			}
		})
	}

	mapcontentstests := []struct {
		name        string
		elfFileName string
		invalidate  bool
		want        []int
		wantErr     error
	}{
		{
			name:        "Test map contents",
			elfFileName: "../../test-data/test.map.bpf.elf",
			invalidate:  false,
			want:        []int{MAP_TYPE_1, MAP_KEY_SIZE_1, MAP_VALUE_SIZE_1, MAP_ENTRIES_1, MAP_FLAGS_1},
			wantErr:     nil,
		},
		{
			name:        "Invalid map contents",
			elfFileName: "../../test-data/test.map.bpf.elf",
			invalidate:  true,
			want:        nil,
			wantErr:     errors.New("missing data in map section"),
		},
	}

	for _, tt := range mapcontentstests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			var parsedMapData []int
			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			assert.NoError(t, err)
			if tt.invalidate {
				var dummySection elf.Section = elf.Section{}
				copiedMapSection := *(elfLoader.mapSection)
				copiedMapSection.SectionHeader = dummySection.SectionHeader
				elfLoader.mapSection = &copiedMapSection
			}
			mapData, err := elfLoader.parseMap(BpfCustomData{})
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for _, data := range mapData {
					parsedMapData = append(parsedMapData, int(data.Type))
					parsedMapData = append(parsedMapData, int(data.KeySize))
					parsedMapData = append(parsedMapData, int(data.ValueSize))
					parsedMapData = append(parsedMapData, int(data.MaxEntries))
					parsedMapData = append(parsedMapData, int(data.Flags))
				}
				assert.Equal(t, tt.want, parsedMapData)
			}
		})
	}

}

func TestParseProg(t *testing.T) {
	progtests := []struct {
		name           string
		elfFileName    string
		want           int
		invalidate     bool
		invalidateRelo bool
		wantErr        error
	}{
		{
			name:        "Missing prog section",
			elfFileName: "../../test-data/test.map.bpf.elf",
			want:        0,
			wantErr:     nil,
		},
		{
			name:        "Test prog data",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        3,
			wantErr:     nil,
		},
		{
			name:        "Test prog data with subprograms",
			elfFileName: "../../test-data/tc.subprog.bpf.elf",
			want:        1,
			wantErr:     nil,
		},
		{
			name:        "Missing prog data",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			invalidate:  true,
			wantErr:     errors.New("missing data in prog section"),
		},
		{
			name:           "Missing relo data",
			elfFileName:    "../../test-data/tc.ingress.bpf.elf",
			invalidateRelo: true,
			wantErr:        errors.New("failed to apply relocation: unable to parse relocation entries...."),
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			assert.NoError(t, err)

			mapData, err := elfLoader.parseMap(BpfCustomData{})
			assert.NoError(t, err)

			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

			loadedMapData, err := elfLoader.loadMap(mapData)
			assert.NoError(t, err)

			if tt.invalidate {
				for progIndex, progEntry := range elfLoader.progSectionMap {
					var dummySection elf.Section = elf.Section{}
					copiedprogSection := *(progEntry.progSection)
					copiedprogSection.SectionHeader = dummySection.SectionHeader
					progEntry.progSection = &copiedprogSection
					elfLoader.progSectionMap[progIndex] = progEntry
				}
			}

			if tt.invalidateRelo {
				for progIndex, reloSection := range elfLoader.reloSectionMap {
					var dummySection elf.Section = elf.Section{}
					copiedreloSection := *(reloSection)
					copiedreloSection.SectionHeader = dummySection.SectionHeader
					reloSection = &copiedreloSection
					elfLoader.reloSectionMap[progIndex] = reloSection
				}
			}

			parsedProgData, err := elfLoader.parseProg(loadedMapData)

			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				progCount := len(parsedProgData)
				assert.Equal(t, tt.want, progCount)
			}
		})
	}

}

func TestRecovery(t *testing.T) {

	utils.Mount_bpf_fs()
	defer utils.Unmount_bpf_fs()

	progtests := []struct {
		name          string
		elfFileName   string
		wantMap       int
		wantProg      int
		recoverGlobal bool
		forceUnMount  bool
		wantErr       error
	}{
		{
			name:          "Recover Global maps",
			elfFileName:   "../../test-data/test.map.bpf.elf",
			wantMap:       1,
			recoverGlobal: true,
			wantErr:       nil,
		},
		{
			name:        "Recover BPF data",
			elfFileName: "../../test-data/recoverydata.bpf.elf",
			wantProg:    3,
			wantErr:     nil,
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()

			bpfSDKclient := New()

			if tt.recoverGlobal {
				_, _, err := bpfSDKclient.LoadBpfFile(m.path, "global")
				if err != nil {
					assert.NoError(t, err)
				}
				recoveredMaps, err := bpfSDKclient.RecoverGlobalMaps()
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					assert.Equal(t, tt.wantMap, len(recoveredMaps))
				}
			} else {
				_, _, err := bpfSDKclient.LoadBpfFile(m.path, "test")
				if err != nil {
					assert.NoError(t, err)
				}

				recoveredData, err := bpfSDKclient.RecoverAllBpfProgramsAndMaps()
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					assert.Equal(t, tt.wantProg, len(recoveredData))
				}
			}
		})
	}
}

func TestGetMapNameFromBPFPinPath(t *testing.T) {
	type args struct {
		pinPath string
	}

	tests := []struct {
		name string
		args args
		want [2]string
	}{
		{
			name: "Ingress Map Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
			},
			want: [2]string{"ingress_map", "hello-udp-748dc8d996-default"},
		},
		{
			name: "Egress Map Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_egress_map",
			},
			want: [2]string{"egress_map", "hello-udp-748dc8d996-default"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1, got2 := GetMapNameFromBPFPinPath(tt.args.pinPath)
			assert.Equal(t, tt.want[0], got1)
			assert.Equal(t, tt.want[1], got2)
		})
	}
}

func TestMapGlobal(t *testing.T) {
	type args struct {
		pinPath string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Ingress Map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
			},
			want: false,
		},
		{
			name: "Egress Map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_egress_map",
			},
			want: false,
		},
		{
			name: "Global",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/test_global",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMapGlobal(tt.args.pinPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProgType(t *testing.T) {

	tests := []struct {
		name     string
		progType string
		want     bool
	}{
		{
			name:     "XDP",
			progType: "xdp",
			want:     true,
		},
		{
			name:     "TC",
			progType: "tc_cls",
			want:     true,
		},
		{
			name:     "Invalid prod",
			progType: "tcc_cls",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProgTypeSupported(tt.progType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadMap(t *testing.T) {
	tests := []struct {
		name       string
		pinType    uint32
		mapFD      uint32
		mapInfo    ebpf_maps.BpfMapInfo
		wantMapID  uint32
		wantErr    bool
		getInfoErr error
		pinPath    string
	}{
		{
			name:      "Successful retrieval of map info",
			pinType:   constdef.PIN_NONE.Index(),
			mapFD:     10,
			mapInfo:   ebpf_maps.BpfMapInfo{Id: 12345},
			wantMapID: 12345,
			wantErr:   false,
		},
		{
			name:       "Map retrieval error",
			pinType:    constdef.PIN_NONE.Index(),
			mapFD:      20,
			getInfoErr: fmt.Errorf("failed to get map info"),
			wantErr:    true,
		},
		{
			name:      "Pinned map retrieval from path",
			pinType:   constdef.PIN_GLOBAL_NS.Index(),
			mapFD:     30,
			mapInfo:   ebpf_maps.BpfMapInfo{Id: 54321},
			wantMapID: 54321,
			wantErr:   false,
			pinPath:   "/sys/fs/bpf/globals/aws/maps/test_map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockBpfMapAPI := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
			mockBpfProgAPI := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)

			// Mock CreateBPFMap to return a BpfMap with MapFD set to tt.mapFD
			mockBpfMapAPI.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: tt.mapFD}, nil).AnyTimes()

			// Mock GetBPFmapInfo or GetMapFromPinPath based on the pin type and error expectation
			if tt.getInfoErr != nil {
				mockBpfMapAPI.EXPECT().GetBPFmapInfo(tt.mapFD).Return(ebpf_maps.BpfMapInfo{}, tt.getInfoErr)
			} else if tt.pinType == constdef.PIN_NONE.Index() {
				mockBpfMapAPI.EXPECT().GetBPFmapInfo(tt.mapFD).Return(tt.mapInfo, nil)
			} else {
				mockBpfMapAPI.EXPECT().GetMapFromPinPath(tt.pinPath).Return(tt.mapInfo, nil)
			}

			// Set up the loader and the map input
			elfLoader := &elfLoader{
				bpfMapApi:  mockBpfMapAPI,
				bpfProgApi: mockBpfProgAPI,
			}
			parsedMapData := []ebpf_maps.CreateEBPFMapInput{
				{
					Name:       "test_map",
					PinOptions: &ebpf_maps.BpfMapPinOptions{Type: tt.pinType, PinPath: tt.pinPath},
				},
			}

			loadedMaps, err := elfLoader.loadMap(parsedMapData)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if loadedMap, exists := loadedMaps["test_map"]; exists {
					assert.Equal(t, tt.wantMapID, loadedMap.MapID)
				} else {
					t.Errorf("Expected map 'test_map' to be loaded")
				}
			}
		})
	}
}

func TestSubprogramParseProg(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

	err = elfLoader.parseSection()
	assert.NoError(t, err)

	// Verify .text section was detected
	assert.NotNil(t, elfLoader.textSection)
	assert.NotEqual(t, -1, elfLoader.textSectionIndex)

	// Verify relocation section exists for .text
	assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])

	// Parse and load maps
	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(mapData))

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(loadedMaps))

	// Parse progs - this exercises getRelocatedTextSection and parseAndApplyRelocSection with textData
	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	// Get the raw section sizes for validation
	textData, err := elfLoader.textSection.Data()
	assert.NoError(t, err)
	textSize := len(textData)
	assert.Greater(t, textSize, 0, ".text section should have data")

	// Verify the program data includes the appended .text section
	for _, progInput := range parsedProgData {
		// Program type should be tc_cls
		assert.Equal(t, "tc_cls", progInput.ProgType)

		// The prog data should be larger than just the tc_cls section alone
		// because .text subprogram data should be appended
		var tcProgSize int
		for idx, entry := range elfLoader.progSectionMap {
			if entry.progType == "tc_cls" {
				sec := elfLoader.progSectionMap[idx]
				secData, _ := sec.progSection.Data()
				tcProgSize = len(secData)
				break
			}
		}
		assert.Greater(t, len(progInput.ProgData), tcProgSize,
			"Program data should include appended .text subprogram data")
		assert.Equal(t, tcProgSize+textSize, len(progInput.ProgData),
			"Program data should be tc_cls section + .text section")
	}
}

// TestChainedSubprogramParseProg tests BPF programs with chained subprogram calls:
// handle_ingress (tc_cls) -> lookup_conntrack (.text) -> do_lookup (.text)
// This verifies that .text-internal calls (resolved by clang at compile time)
// remain valid after .text is appended to the program section.
func TestChainedSubprogramParseProg(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog_chain.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

	err = elfLoader.parseSection()
	assert.NoError(t, err)

	assert.NotNil(t, elfLoader.textSection)
	assert.NotEqual(t, -1, elfLoader.textSectionIndex)
	assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])

	// .text should contain both lookup_conntrack and do_lookup
	textData, err := elfLoader.textSection.Data()
	assert.NoError(t, err)
	textInsns := len(textData) / bpfInsDefSize
	assert.Greater(t, textInsns, 2, ".text should contain multiple subprograms")

	// Verify both functions exist in symbol table under .text section
	symbols, err := elfFile.Symbols()
	assert.NoError(t, err)
	textFuncs := map[string]elf.Symbol{}
	for _, sym := range symbols {
		if int(sym.Section) == elfLoader.textSectionIndex && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
			textFuncs[sym.Name] = sym
		}
	}
	assert.Contains(t, textFuncs, "lookup_conntrack")
	assert.Contains(t, textFuncs, "do_lookup")

	// Parse maps and load
	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(mapData))

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	// Parse progs with chained subprograms
	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	for _, progInput := range parsedProgData {
		assert.Equal(t, "tc_cls", progInput.ProgType)

		// Find tc_cls raw section size
		var tcProgSize int
		for idx, entry := range elfLoader.progSectionMap {
			if entry.progType == "tc_cls" {
				secData, _ := elfLoader.progSectionMap[idx].progSection.Data()
				tcProgSize = len(secData)
				break
			}
		}
		textSize := len(textData)

		// Combined data = tc_cls section + .text section
		assert.Equal(t, tcProgSize+textSize, len(progInput.ProgData),
			"Program data should be tc_cls section + .text section")

		// Verify the BPF_CALL from tc_cls to lookup_conntrack has correct relocation.
		// The call instruction is at the start of tc_cls (offset 0).
		// After appending .text, lookup_conntrack is at insn index (tcProgSize/bpfInsDefSize).
		// BPF call Imm = target_insn_idx - call_insn_idx - 1
		callInsnOffset := 0
		callInsn := progInput.ProgData[callInsnOffset]
		assert.Equal(t, uint8(0x85), callInsn, "First insn should be BPF_CALL")

		// src_reg should be BPF_PSEUDO_CALL (1)
		srcReg := progInput.ProgData[callInsnOffset+1] >> 4
		assert.Equal(t, uint8(1), srcReg, "BPF_CALL should have BPF_PSEUDO_CALL src_reg")

		tcInsnCount := tcProgSize / bpfInsDefSize
		lookupOffset := textFuncs["lookup_conntrack"].Value
		expectedTargetInsn := tcInsnCount + int(lookupOffset)/bpfInsDefSize
		expectedImm := int32(expectedTargetInsn - 0 - 1)
		actualImm := int32(binary.LittleEndian.Uint32(progInput.ProgData[callInsnOffset+4 : callInsnOffset+8]))
		assert.Equal(t, expectedImm, actualImm,
			"BPF_CALL Imm should point to lookup_conntrack in appended .text")

		// Verify .text-internal call: lookup_conntrack -> do_lookup
		// Clang resolves this at compile time. The call insn is at the start of
		// lookup_conntrack within .text. After appending, it's at offset tcProgSize+0.
		chainCallOffset := tcProgSize + int(lookupOffset)
		chainCallInsn := progInput.ProgData[chainCallOffset]
		assert.Equal(t, uint8(0x85), chainCallInsn, "lookup_conntrack first insn should be BPF_CALL")

		chainSrcReg := progInput.ProgData[chainCallOffset+1] >> 4
		assert.Equal(t, uint8(1), chainSrcReg, "Chained call should have BPF_PSEUDO_CALL src_reg")

		// The Imm for the .text-internal call should be the relative offset to do_lookup
		doLookupOffset := textFuncs["do_lookup"].Value
		chainCallInsnIdx := int(lookupOffset) / bpfInsDefSize
		doLookupInsnIdx := int(doLookupOffset) / bpfInsDefSize
		expectedChainImm := int32(doLookupInsnIdx - chainCallInsnIdx - 1)
		actualChainImm := int32(binary.LittleEndian.Uint32(progInput.ProgData[chainCallOffset+4 : chainCallOffset+8]))
		assert.Equal(t, expectedChainImm, actualChainImm,
			"Chained BPF_CALL Imm should point from lookup_conntrack to do_lookup within .text")
	}
}
