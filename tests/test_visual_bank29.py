"""Integration contract between model labels, registry domains and visual verdicts."""
import base64
import json
import os
from pathlib import Path

import pytest

from core.brands import BRANDS
from schemas.visual import BoundingBox, DetectedLogo
from services import visual_detector as visual

ROOT = Path(__file__).resolve().parents[1]
CLASSES = json.loads((ROOT / 'visual_identity/class_map.json').read_text(encoding='utf-8'))


def logo(label):
    return DetectedLogo(brand=label, confidence=.96, bbox=BoundingBox(x1=1,y1=2,x2=100,y2=40))


def test_class_ids_and_registry_match_shipped_manifest():
    assert len(CLASSES) == 29
    assert [r['class_id'] for r in CLASSES] == list(range(29))
    assert [r['name'] for r in CLASSES] == list(visual._CLASS_TO_BRAND)
    assert (ROOT / 'visual_identity/classes.txt').read_text().splitlines() == [r['name'] for r in CLASSES]
    for row in CLASSES:
        assert visual._CLASS_TO_BRAND[row['name']] == row['backend_brand']
        assert visual.AUTHORIZED_DOMAINS[row['name']] == BRANDS[row['backend_brand']]['domains']


@pytest.mark.parametrize('row', CLASSES, ids=lambda r:r['name'])
def test_every_label_and_registry_alias_normalizes(row):
    name=row['name']
    for label in [name,name.lower(),name.upper().replace(' ','_'),name.lower().replace(' ','-'),name.replace(' ','')]:
        assert visual._normalize_brand(label) == name
    if row['backend_brand'] != 'DBS / POSB':
        assert visual._normalize_brand(row['backend_brand']) == name


@pytest.mark.parametrize('row', CLASSES, ids=lambda r:r['name'])
def test_all_domains_and_common_domain_tricks(row):
    name=row['name'];detection=logo(name)
    for domain in BRANDS[row['backend_brand']]['domains']:
        for host in [domain,'login.'+domain]:
            result=visual.evaluate_logo_domain(f'https://{host}/login',[detection])
            assert result.risk_level == 'safe'
            assert any(d.brand == name for d in result.detected_logos)
        for url in [f'https://{domain}.attacker.example/login',f'https://attacker.example/{domain}',
                    f'https://{domain}@attacker.example/login',f'https://secure-{domain}/login']:
            assert visual.evaluate_logo_domain(url,[detection]).risk_level == 'dangerous'


def test_shared_dbs_posb_domains_preserve_both_labels_without_global_bypass(monkeypatch):
    monkeypatch.setattr(visual,'ALL_TRUSTED_DOMAINS',[])
    for host in BRANDS['DBS / POSB']['domains']:
        for name in ['DBS','POSB']:
            result=visual.evaluate_logo_domain(f'https://{host}/',[logo(name)])
            assert result.risk_level == 'safe'
            assert result.detected_logos[0].brand == name


def test_untrained_brand_label_is_not_silently_mapped():
    assert visual._normalize_brand('Unknown Bank') is None


@pytest.fixture(scope='module')
def real_detector_and_image():
    path=Path(os.environ.get('PHISHGUARD_VISUAL_SMOKE_IMAGE',''))
    if not path.is_file():
        pytest.skip('Set PHISHGUARD_VISUAL_SMOKE_IMAGE to an authentic GXBank screenshot for real-model integration.')
    detector=visual.VisualLogoDetector()
    return detector,base64.b64encode(path.read_bytes()).decode('ascii')


def test_real_model_class_order_and_gxbank_domain(real_detector_and_image):
    detector,screenshot=real_detector_and_image
    detections,warning=detector.detect(screenshot)
    assert warning is None
    assert detector._model.names == dict(enumerate(r['name'] for r in CLASSES))
    assert any(d.brand=='GXBank' for d in detections)
    result=visual.evaluate_logo_domain('https://www.gxbank.my/',detections)
    assert result.risk_level=='safe'


async def test_real_model_reaches_api_r8_for_foreign_login(test_client,real_detector_and_image):
    from main import app
    detector,screenshot=real_detector_and_image
    previous=app.state.visual_detector
    app.state.visual_detector=detector
    try:
        response=await test_client.post('/api/v1/analyze',json={
            'url':'https://rewards-portal.example/login',
            'dom_content':"<form><input name='user'><input type='password' name='pass'></form>",
            'screenshot':screenshot,
        })
    finally:
        app.state.visual_detector=previous
    assert response.status_code==200,response.text
    body=response.json()
    assert body['rule']=='R8_VISUAL_BRAND_MISMATCH',body
    assert body['verdict']=='BLOCK_RENDER'
    assert body['visual']['status']=='ok'
    assert any(d['brand']=='GXBank' for d in body['visual']['detected_logos'])
