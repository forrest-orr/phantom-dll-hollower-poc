define("stripColumnsContainer",["lodash","santa-components","componentsCore","santa-core-utils","react","components","backgroundCommon"],function(i,e,t,n,r,o,s){return function(i){var e={};function t(n){if(e[n])return e[n].exports;var r=e[n]={i:n,l:!1,exports:{}};return i[n].call(r.exports,r,r.exports,t),r.l=!0,r.exports}return t.m=i,t.c=e,t.d=function(i,e,n){t.o(i,e)||Object.defineProperty(i,e,{enumerable:!0,get:n})},t.r=function(i){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(i,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(i,"__esModule",{value:!0})},t.t=function(i,e){if(1&e&&(i=t(i)),8&e)return i;if(4&e&&"object"==typeof i&&i&&i.__esModule)return i;var n=Object.create(null);if(t.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:i}),2&e&&"string"!=typeof i)for(var r in i)t.d(n,r,function(e){return i[e]}.bind(null,r));return n},t.n=function(i){var e=i&&i.__esModule?function(){return i.default}:function(){return i};return t.d(e,"a",e),e},t.o=function(i,e){return Object.prototype.hasOwnProperty.call(i,e)},t.p="",t(t.s=1076)}({0:function(e,t){e.exports=i},10:function(i,e){i.exports=n},1076:function(i,e,t){var n,r;function o(i){if(Array.isArray(i)){for(var e=0,t=Array(i.length);e<i.length;e++)t[e]=i[e];return t}return Array.from(i)}n=[t(15),t(0),t(3),t(18),t(46),t(2),t(10)],void 0===(r=function(i,e,t,n,r,s,a){"use strict";var p={displayName:"StripColumnsContainer",mixins:[n.mediaCommon.mediaLogicMixins.fill,t.mixins.skinBasedComp,r.mixins.backgroundDetectionMixin,t.mixins.createChildComponentMixin],propTypes:{style:s.santaTypesDefinitions.Component.style.isRequired,isMeshLayoutMechanism:s.santaTypesDefinitions.Layout.isMeshLayoutMechanism,compProp:s.santaTypesDefinitions.Component.compProp,isMobileView:s.santaTypesDefinitions.isMobileView.isRequired,isPreviewMode:s.santaTypesDefinitions.isPreviewMode.isRequired,siteWidth:s.santaTypesDefinitions.siteWidth.isRequired,getScreenWidth:s.santaTypesDefinitions.getScreenWidth.isRequired,getScrollBarWidth:s.santaTypesDefinitions.getScrollBarWidth.isRequired,browser:s.santaTypesDefinitions.Browser.browser.isRequired,childrenData:s.santaTypesDefinitions.ColumnsContainer.childrenData.isRequired},statics:{compSpecificIsDomOnlyOverride:function(){return!1},behaviors:n.mediaCommon.mediaBehaviors.fill},componentDidLayout:function(){var i=this.props.getScrollBarWidth(),e=this.props.getScreenWidth(),t=this.lastScrollBarWidth!==i,n=this.lastScreenWidth!==e;this.props.isMobileView||!t&&!n||(this.lastScrollBarWidth=i,this.lastScreenWidth=e,this.registerReLayout(),this.forceUpdate())},getDefaultSkinName:function(){return"wysiwyg.viewer.skins.stripContainer.DefaultStripContainer"},getMobileSkinProperties:function(){var t=this.props.compProp.rowMargin,n=this.props.siteWidth,r=i.Children.map(this.props.children,function(e){var r={position:"absolute",top:t,height:this.props.childrenData[e.props.id].height,left:0,width:n};t+=r.height+this.props.compProp.columnsMargin;var o={width:n,height:this.props.childrenData[e.props.id].height};return e=i.cloneElement(e,{rootStyle:r,mediaDimensions:o})},this),o=t-this.props.compProp.columnsMargin+this.props.compProp.rowMargin;return{"":e.assign({tagName:"section",style:{height:o}},this.getDataAttributesForAnchorLayout()),background:this.createFillLayers({mediaDimensions:{width:n}}),inlineContent:{children:r}}},getDataAttributesForAnchorLayout:function(){return{"data-col-margin":this.props.compProp.columnsMargin,"data-row-margin":this.props.compProp.rowMargin}},isScreenWidth:function(){return this.props.compProp.fullWidth},getDesktopRelativeSkinProperties:function(){var t=this.props,n=t.siteWidth,r=t.childrenData,s=t.children,a=t.style,p=t.isMeshLayoutMechanism,l=this.props.compProp,h=l.fullWidth,c=l.frameMargin,u=l.columnsMargin,d=l.siteMargin,m=l.rowMargin,f=e.size(this.props.children),g=n-2*d,y=n-2*c,M=y-u*(f-1),v=i.Children.map(s,function(i){var e=i.props;return r[e.id].width}),w=e.sum(v),b=e.map(v,function(i){return Math.round(i*M/w)});b[0]+=M-e.sum(b);var S=h?"100%":n,D=e.defaults({left:0,width:S,minWidth:g+"px"},p&&{height:"auto"},a),C=i.Children.map(s,function(e,t){var n=e.props.id,o=b[t],s=r[n],a=s.alignment,l=s.height,h=s.width,c={width:o,alignment:a/100},d={position:"relative",width:"100%",left:0,flex:o,marginLeft:t?u+"px":0,minWidth:o+"px",top:p?0:m,marginTop:p?m:0,marginBottom:p?m:0,height:p?"":l},f={width:h,height:l};return e=i.cloneElement(e,{rootStyle:d,contentArea:c,mediaDimensions:f})}),x={width:"calc(100% - "+2*d+"px)",minWidth:n},P={position:"relative",width:"calc(100% - "+2*(d+c)+"px)",minWidth:y+"px"},W=this.props.isPreviewMode?this.createContentAreaMarker(S):null;return{"":e.assign({tagName:"section",style:D,"data-responsive":"true"},this.isScreenWidth()&&{"data-is-screen-width":!0},this.getDataAttributesForAnchorLayout()),background:this.createFillLayers({bgStyle:x,mediaDimensions:{width:n}}),inlineContent:{style:P,children:[W].concat(o(C))}}},createContentAreaMarker:function(e){var t=a.contentAreaUtil.getContentAreaMarkingElement({alignment:.5,width:e},this.props.id);return i.createElement.apply(null,t)},getMobileSkinPropertiesForMesh:function(){var e=this.props.compProp.rowMargin,t=this.props.siteWidth,n=i.Children.map(this.props.children,function(e,n){var r={position:"relative",marginBottom:n===this.props.children.length-1?0:this.props.compProp.columnsMargin},o={width:t,height:this.props.childrenData[e.props.id].height};return e=i.cloneElement(e,{isMobileResponsive:!0,rootStyle:r,inlineParentStyle:{position:"relative"},inlineStyle:{position:"relative"},mediaDimensions:o,containerStyle:{position:"relative"}})},this),r={position:"relative",padding:e+"px 0"};return{"":{tagName:"section","data-mobile-responsive":"true",style:{height:"auto"}},background:this.createFillLayers({mediaDimensions:{width:t}}),inlineContent:{style:r,children:n}}},getSkinProperties:function(){return this.props.isMobileView?this.props.isMeshLayoutMechanism?this.getMobileSkinPropertiesForMesh():this.getMobileSkinProperties():this.getDesktopRelativeSkinProperties()}};return t.compRegistrar.register("wysiwyg.viewer.components.StripColumnsContainer",p),p}.apply(e,n))||(i.exports=r)},15:function(i,e){i.exports=r},18:function(i,e){i.exports=o},2:function(i,t){i.exports=e},3:function(i,e){i.exports=t},46:function(i,e){i.exports=s}})});
//# sourceMappingURL=stripColumnsContainer.min.js.map