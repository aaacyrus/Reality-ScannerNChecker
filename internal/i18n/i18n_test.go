package i18n

import "testing"

func TestTranslationCatalogsHaveMatchingKeys(t *testing.T) {
	t.Parallel()
	for key := range english {
		if _, ok := traditionalChinese[key]; !ok {
			t.Errorf("Traditional Chinese catalog is missing %q", key)
		}
	}
	for key := range traditionalChinese {
		if _, ok := english[key]; !ok {
			t.Errorf("English catalog is missing %q", key)
		}
	}
}
