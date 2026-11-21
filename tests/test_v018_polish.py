"""v0.18 regression checks for polish that must preserve existing behavior."""
from pathlib import Path
from bs4 import BeautifulSoup
from app.main import app

ROOT = Path(__file__).resolve().parents[1]


def test_plextrac_source_label_only_changed():
    source = (ROOT / 'app/templates/imports.html').read_text()
    document = BeautifulSoup(source, 'html.parser')
    source_option = document.select_one('option[value="plextrac_json"]')
    assert source_option is not None
    assert source_option.text == 'PlexTrac PTRAC'
    assert 'PlexTrac PTRAC</h3>' in source
    assert 'Bulletproof' not in source
    assert "source.value==='plextrac_json' ? '.json,.ptrac'" in source


def test_work_item_top_cards_share_css_grid_row():
    page = (ROOT / 'app/templates/work_item_detail.html').read_text()
    css = (ROOT / 'app/static/site.css').read_text()
    doc = BeautifulSoup(page, 'html.parser')
    assert doc.select_one('.work-detail-layout .work-assignment-panel')
    assert doc.select_one('.work-detail-layout .work-status-panel')
    assert '.work-detail-layout .work-assignment-panel {grid-column:1;grid-row:1;}' in css
    assert '.work-detail-layout .work-status-panel {grid-column:2;grid-row:1;}' in css
    assert 'grid-template-columns:minmax(0,1fr)' in css


def test_edit_forms_use_consistent_centered_container():
    for template in ('team_edit.html', 'routing_edit.html'):
        page = (ROOT / 'app/templates' / template).read_text()
        assert '<div class="centered-editor">' in page
        assert 'style="max-width:' not in page
    css = (ROOT / 'app/static/site.css').read_text()
    assert '.centered-editor {width:100%;max-width:800px;margin-inline:auto;}' in css


def test_release_version_and_route_compatibility():
    import tomllib
    config = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    assert config['project']['version'] == '0.18.0'
    assert app.version == '0.18.0'
    html = (ROOT / 'app/templates/routing_edit.html').read_text()
    assert 'action="/ownership/routing/{{rule.id}}/edit"' in html
    assert 'action="/ownership/teams/{{team.id}}"' in (ROOT / 'app/templates/team_edit.html').read_text()


def test_readme_is_public_facing_and_installs_on_port_8001():
    readme = (ROOT / 'README.md').read_text()
    assert '--port 8001' in readme
    assert 'python -m scripts.create_admin' in readme
    assert 'docs/ARCHITECTURE.md' in readme
    assert 'CAPSTONE_STATUS' not in readme


def test_create_work_item_form_is_centered_without_changing_its_action():
    page = (ROOT / 'app/templates/work_item_new.html').read_text()
    document = BeautifulSoup(page, 'html.parser')
    wrapper = document.select_one('.work-item-new-editor')
    assert wrapper is not None
    assert wrapper.select_one('.heading h1').get_text(strip=True) == 'New work item'
    assert wrapper.select_one('form[action="/work-items/create"]') is not None
    assert wrapper.select_one('.panel.form-narrow') is not None
    css = (ROOT / 'app/static/site.css').read_text()
    assert '.work-item-new-editor {max-width:660px;margin-inline:auto;}' in css
