package throttle

import "testing"

func TestGCRAPacingRoundsUp(t *testing.T) {
	for _, test := range []struct {
		rps      float64
		interval int64
	}{
		{1.0 / 60, 60000}, {3.0 / 60, 20000}, {10.0 / 6, 600},
		{3, 334}, {7, 143}, {100, 10}, {2000, 1},
	} {
		params := newGCRAParams(test.rps, 5)
		if params.emissionIntervalMS != test.interval || params.burstOffsetMS != test.interval*5 {
			t.Errorf("rps %v: params %+v, want interval %d, burst offset %d", test.rps, params, test.interval, test.interval*5)
		}
		if float64(params.emissionIntervalMS) < 1000/test.rps {
			t.Errorf("rps %v: pacing exceeds configured rate", test.rps)
		}
	}
}
