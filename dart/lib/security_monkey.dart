library security_monkey;

import 'package:angular/angular.dart';
import 'package:angular_ui/angular_ui.dart';
import 'dart:math';
import 'dart:js'; // select2 is still in JavaScript
import 'dart:html'; // select2 querySelector
import 'dart:convert';
import 'package:di/di.dart';
import 'dart:async';

// NG-infinite-scroll
import 'package:ng_infinite_scroll/ng_infinite_scroll.dart';

// Hammock
import 'package:hammock/hammock.dart';
import 'model/hammock_config.dart';

// Services
import 'service/justification_service.dart';
import 'service/username_service.dart';

// Model
import 'model/Account.dart';
import 'model/Issue.dart';
import 'model/Item.dart';
import 'model/Revision.dart';
import 'model/RevisionComment.dart';
import 'model/ItemComment.dart';
import 'model/UserSetting.dart';
import 'model/network_whitelist_entry.dart';
import 'model/ignore_entry.dart';
import 'model/auditorsetting.dart';

// Routing
import 'routing/securitymonkey_router.dart';
// import 'package:security_monkey/routing/securitymonkey_router.dart' show param_from_url, param_to_url, map_from_url, map_to_url;

// HTTP Interceptor
import 'util/constants.dart';
part 'interceptor/global_http_interceptor.dart';

// Interceptor Error Messages
part 'service/messages.dart';

// Parent Component
part 'component/paginated_table/paginated_table.dart';

// Part components
part 'component/account_view_component/account_view_component.dart';
part 'component/issue_table_component/issue_table_component.dart';
part 'component/settings_component/settings_component.dart';
part 'component/revision_table_component/revision_table_component.dart';
part 'component/item_table_component/item_table_component.dart';
part 'component/search_bar_component/search_bar_component.dart';
part 'component/search_page_component/search_page_component.dart';
part 'component/signout_component/signout_component.dart';
part 'component/revision/revision_component.dart';
part 'component/itemdetails/itemdetails_component.dart';
part 'component/modal_justify_issues/modal_justify_issues.dart';
part 'component/whitelist_view_component/whitelist_view_component.dart';
part 'component/ignore_entry_component/ignore_entry_component.dart';
part 'component/username_component/username_component.dart';
part 'component/settings/auditor_settings_component/auditor_settings_component.dart';

class SecurityMonkeyModule extends Module {

  SecurityMonkeyModule() {

    // AngularUI
    install(new AngularUIModule());

    // Hammock (like restangular)
    install(new Hammock());
    Injector inj;
    bind(HammockConfig, toValue: createHammockConfig(inj));

    // NG-infinite-scroll
    install(new InfiniteScrollModule());

    // Components
    bind(ItemDetailsComponent);
    bind(RevisionTableComponent);
    bind(ItemTableComponent);
    bind(RevisionComponent);
    bind(IssueTableComponent);
    bind(AccountViewComponent);
    bind(SearchPageComponent);
    bind(SearchBarComponent);
    bind(SignoutComponent);
    bind(SettingsComponent);
    bind(ModalJustifyIssues);
    bind(WhitelistViewComponent);
    bind(IgnoreEntryComponent);
    bind(UsernameComponent);
    bind(AuditorSettingsComponent);

    // Services
    bind(JustificationService);
    bind(UsernameService);
    bind(Messages);

    // Routing
    bind(RouteInitializerFn, toValue: securityMonkeyRouteInitializer);
    bind(NgRoutingUsePushState,
        toValue: new NgRoutingUsePushState.value(false));
  }
}
